//go:build with_gvisor

package netstack

import (
	"context"
	"fmt"
	"io"
	"log"
	"runtime"

	tunstackpkg "whispera/internal/tunstack"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Config описывает базовые параметры userspace‑стека gVisor netstack.
type Config struct {
	// MTU для виртуального NIC (обычно совпадает с MTU TUN).
	MTU uint32
	// EnableIPv6 включает обработку IPv6 пакетов.
	EnableIPv6 bool
	// Debug включает подробный лог трафика на уровне netstack.
	Debug bool
	// TCPMaxInFlight ограничивает количество одновременных TCP‑handshake,
	// обрабатываемых через Forwarder.
	TCPMaxInFlight int
}

// DefaultConfig возвращает минимальную конфигурацию по умолчанию.
func DefaultConfig() Config {
	return Config{
		MTU:           1500,
		EnableIPv6:    true,
		Debug:         false,
		TCPMaxInFlight: 1024,
	}
}

// TCPConnHandler вызывается при появлении нового входящего TCP‑соединения
// в netstack. На этом уровне мы уже знаем 5‑tuple (FlowKey) и имеем
// tcpip.Endpoint для обмена байтами.
//
// typically над этим будет натянут STREAM‑слой/SessionManager.
type TCPConnHandler func(flow tunstackpkg.FlowKey, ep tcpip.Endpoint)

// UDPConnHandler вызывается при появлении нового UDP‑сеанса.
type UDPConnHandler func(flow tunstackpkg.FlowKey, ep tcpip.Endpoint)

// Stack инкапсулирует gVisor netstack и связывает его с TUN‑интерфейсом.
//
// Схема:
//   TUN (io.ReadWriter) <-> netstack NIC (link/channel.Endpoint) <-> gVisor stack.Stack
type Stack struct {
	cfg Config

	// raw TUN интерфейс, из которого читаем/в который пишем IP‑пакеты.
	tun io.ReadWriter

	// userspace стек gVisor.
	s    *stack.Stack
	nic  *channel.Endpoint
	nicID tcpip.NICID

	// TCP/UDP forwarders.
	tcpFwd *tcp.Forwarder
	udpFwd *udp.Forwarder

	// callbacks наверх (tunstack/STREAM).
	onTCP TCPConnHandler
	onUDP UDPConnHandler

	// Контекст для фоновых горутин (drain NIC → TUN, read TUN → InjectInbound).
	ctx    context.Context
	cancel context.CancelFunc
}

// NewStack поднимает gVisor netstack поверх заданного TUN‑интерфейса.
//
// Внешний код должен:
//   1) передать io.ReadWriter TUN (например, *tun.Interface);
//   2) настроить обработчики OnTCP/OnUDP (через SetTCPHandler/SetUDPHandler);
//   3) вызвать Run() в отдельной горутине.
func NewStack(tun io.ReadWriter, cfg Config) (*Stack, error) {
	if tun == nil {
		return nil, fmt.Errorf("netstack.NewStack: tun is nil")
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}
	if cfg.TCPMaxInFlight <= 0 {
		cfg.TCPMaxInFlight = 1024
	}

	// Создаём userspace стек.
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})

	if cfg.EnableIPv6 {
		s.NetworkProtocolOption(ipv6.ProtocolNumber, nil) // просто убеждаемся, что протокол доступен
	}

	// Создаём channel‑endpoint, который будет нашим NIC.
	nic := channel.New(1024, cfg.MTU, "" /* linkAddr */)
	const nicID = tcpip.NICID(1)
	if err := s.CreateNIC(nicID, nic); err != nil {
		return nil, fmt.Errorf("netstack.CreateNIC: %w", err)
	}

	// Маршрутизация: всё IPv4/IPv6 идёт через этот NIC.
	routeTable := []tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
	}
	if cfg.EnableIPv6 {
		routeTable = append(routeTable, tcpip.Route{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		})
	}
	s.SetRouteTable(routeTable)

	ctx, cancel := context.WithCancel(context.Background())

	ns := &Stack{
		cfg:   cfg,
		tun:   tun,
		s:     s,
		nic:   nic,
		nicID: nicID,
		ctx:   ctx,
		cancel: cancel,
	}

	// Настраиваем TCP/UDP forwarder'ы.
	ns.tcpFwd = tcp.NewForwarder(s, 0 /* rcvWnd=default */, cfg.TCPMaxInFlight, ns.handleTCPForwarderRequest)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, ns.tcpFwd.HandlePacket)

	ns.udpFwd = udp.NewForwarder(s, ns.handleUDPForwarderRequest)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, ns.udpFwd.HandlePacket)

	return ns, nil
}

// SetTCPHandler регистрирует callback для новых TCP‑соединений.
func (ns *Stack) SetTCPHandler(h TCPConnHandler) {
	ns.onTCP = h
}

// SetUDPHandler регистрирует callback для новых UDP‑сеансов.
func (ns *Stack) SetUDPHandler(h UDPConnHandler) {
	ns.onUDP = h
}

// Close останавливает фоновые горутины и освобождает ресурсы.
func (ns *Stack) Close() {
	if ns.cancel != nil {
		ns.cancel()
	}
	if ns.nic != nil {
		ns.nic.Close()
	}
}

// InjectInboundPacket инжектит сырой IP‑пакет в netstack через NIC.
// Используется внешним dataplane (tunstack/TUN‑читателем), чтобы netstack
// обрабатывал выбранные потоки (например, только TCP), не захватывая
// эксклюзивно чтение из TUN.
func (ns *Stack) InjectInboundPacket(pkt []byte) error {
	return ns.injectInbound(pkt)
}

// StartNICToTUN запускает фоновую горутину, которая вычитывает outbound‑пакеты
// из NIC (channel.Endpoint) и отправляет их в TUN в виде сырых IP.
//
// В отличие от Run(), этот метод не читает TUN и может использоваться в связке
// с внешним читателем (tunstack.Run()), чтобы разделить ответственность:
//   - tunstack читает из TUN и, при необходимости, дублирует пакеты в netstack;
//   - netstack генерирует исходящие IP‑пакеты для ОС/клиента.
func (ns *Stack) StartNICToTUN() {
	go ns.drainNICToTUN()
}

// Run запускает основной цикл:
//   1) читает IP‑пакеты из TUN и инжектит их в netstack;
//   2) вычитывает пакеты из NIC и пишет их обратно в TUN.
//
// Вызывать из отдельной горутины; блокирует до ошибки чтения из TUN
// или отмены контекста.
func (ns *Stack) Run() error {
	if ns.tun == nil || ns.nic == nil {
		return fmt.Errorf("netstack.Run: not initialized")
	}

	// Фоновая горутина: outbound из netstack → TUN.
	go ns.drainNICToTUN()

	buf := make([]byte, 65535)
	for {
		select {
		case <-ns.ctx.Done():
			return nil
		default:
		}

		n, err := ns.tun.Read(buf)
		if err != nil {
			return fmt.Errorf("netstack.Run: TUN read error: %w", err)
		}
		if n <= 0 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		if err := ns.injectInbound(pkt); err != nil && ns.cfg.Debug {
			log.Printf("[NETSTACK] injectInbound error: %v", err)
		}
	}
}

// injectInbound разбирает IP‑версию и инжектит пакет в netstack через NIC.
func (ns *Stack) injectInbound(pkt []byte) error {
	if len(pkt) < 1 {
		return nil
	}
	version := pkt[0] >> 4
	var proto tcpip.NetworkProtocolNumber
	switch version {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		if !ns.cfg.EnableIPv6 {
			return nil
		}
		proto = ipv6.ProtocolNumber
	default:
		// Неизвестная версия IP.
		return nil
	}

	// Заворачиваем payload в buffer.Buffer.
	v := buffer.NewView(len(pkt))
	copy(v.AsSlice(), pkt)
	var payload buffer.Buffer
	payload.Append(v)

	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: payload,
	})
	pb.NetworkProtocolNumber = proto

	ns.nic.InjectInbound(proto, pb)
	pb.DecRef()

	return nil
}

// drainNICToTUN вычитывает outbound‑пакеты из NIC (channel.Endpoint) и
// отправляет их в TUN в виде сырых IP.
func (ns *Stack) drainNICToTUN() {
	for {
		select {
		case <-ns.ctx.Done():
			return
		default:
		}

		pkt := ns.nic.ReadContext(ns.ctx)
		if pkt == nil {
			// ОПТИМИЗАЦИЯ: Убираем sleep для производительности
			runtime.Gosched()
			continue
		}

		v := pkt.ToView()
		data := v.AsSlice()
		if len(data) > 0 {
			if _, err := ns.tun.Write(data); err != nil && ns.cfg.Debug {
				log.Printf("[NETSTACK] TUN write error: %v", err)
			}
		}
		v.Release()

		pkt.DecRef()
	}
}

// handleTCPForwarderRequest обрабатывает новый входящий TCP‑SYN через Forwarder.
// Здесь мы строим FlowKey и, при наличии обработчика, создаём endpoint
// и отдаём его наверх.
func (ns *Stack) handleTCPForwarderRequest(req *tcp.ForwarderRequest) {
	id := req.ID()

	// Строим FlowKey в терминах tunstack.
	fk := tunstackpkg.FlowKey{
		Proto:     6,
		IPVersion: 4,
	}

	// IPv4/IPv6 разбираем по длине адреса.
	if id.LocalAddress.Len() == netIPv4Len && id.RemoteAddress.Len() == netIPv4Len {
		copy(fk.SrcIP[0:4], id.RemoteAddress.AsSlice())
		copy(fk.DstIP[0:4], id.LocalAddress.AsSlice())
		fk.IPVersion = 4
	} else {
		copy(fk.SrcIP[:], id.RemoteAddress.AsSlice())
		copy(fk.DstIP[:], id.LocalAddress.AsSlice())
		fk.IPVersion = 6
	}
	fk.SrcPort = id.RemotePort
	fk.DstPort = id.LocalPort

	if ns.onTCP == nil {
		// Никто не обрабатывает — корректнее всего просто завершить запрос, не открывая соединение.
		req.Complete(false)
		return
	}

	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		if ns.cfg.Debug {
			log.Printf("[NETSTACK] TCP CreateEndpoint error for flow %s: %v", fk.String(), err)
		}
		req.Complete(true) // отправляем RST.
		return
	}

	// Соединение создано, завершаем запрос без RST.
	req.Complete(false)

	ns.onTCP(fk, ep)
}

const netIPv4Len = 4

// handleUDPForwarderRequest обрабатывает новый UDP‑сеанс.
func (ns *Stack) handleUDPForwarderRequest(req *udp.ForwarderRequest) (handled bool) {
	id := req.ID()

	fk := tunstackpkg.FlowKey{
		Proto:     17,
		IPVersion: 4,
	}
	if id.LocalAddress.Len() == netIPv4Len && id.RemoteAddress.Len() == netIPv4Len {
		copy(fk.SrcIP[0:4], id.RemoteAddress.AsSlice())
		copy(fk.DstIP[0:4], id.LocalAddress.AsSlice())
		fk.IPVersion = 4
	} else {
		copy(fk.SrcIP[:], id.RemoteAddress.AsSlice())
		copy(fk.DstIP[:], id.LocalAddress.AsSlice())
		fk.IPVersion = 6
	}
	fk.SrcPort = id.RemotePort
	fk.DstPort = id.LocalPort

	if ns.onUDP == nil {
		// Никто не обработал — вернём false, стек сам может послать ICMP port unreachable.
		return false
	}

	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		if ns.cfg.Debug {
			log.Printf("[NETSTACK] UDP CreateEndpoint error for flow %s: %v", fk.String(), err)
		}
		return false
	}

	ns.onUDP(fk, ep)
	return true
}


