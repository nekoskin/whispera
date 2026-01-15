package tun_handler

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintun = syscall.NewLazyDLL("wintun.dll")

	procWintunCreateAdapter        = wintun.NewProc("WintunCreateAdapter")
	procWintunOpenAdapter          = wintun.NewProc("WintunOpenAdapter")
	procWintunCloseAdapter         = wintun.NewProc("WintunCloseAdapter")
	procWintunDeleteDriver         = wintun.NewProc("WintunDeleteDriver")
	procWintunGetAdapterLUID       = wintun.NewProc("WintunGetAdapterLUID")
	procWintunStartSession         = wintun.NewProc("WintunStartSession")
	procWintunEndSession           = wintun.NewProc("WintunEndSession")
	procWintunGetReadWaitEvent     = wintun.NewProc("WintunGetReadWaitEvent")
	procWintunReceivePacket        = wintun.NewProc("WintunReceivePacket")
	procWintunReleaseReceivePacket = wintun.NewProc("WintunReleaseReceivePacket")
	procWintunAllocateSendPacket   = wintun.NewProc("WintunAllocateSendPacket")
	procWintunSendPacket           = wintun.NewProc("WintunSendPacket")
)

type WINTUN_ADAPTER_HANDLE uintptr
type WINTUN_SESSION_HANDLE uintptr

func createAdapter(name string, tunnelType string, requestedGUID *windows.GUID) (WINTUN_ADAPTER_HANDLE, error) {
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	tunnelType16, err := windows.UTF16PtrFromString(tunnelType)
	if err != nil {
		return 0, err
	}

	r0, _, e1 := syscall.SyscallN(procWintunCreateAdapter.Addr(),
		uintptr(unsafe.Pointer(name16)),
		uintptr(unsafe.Pointer(tunnelType16)),
		uintptr(unsafe.Pointer(requestedGUID)))

	if r0 == 0 {
		if e1 != 0 {
			return 0, e1
		}
		return 0, syscall.EINVAL
	}
	return WINTUN_ADAPTER_HANDLE(r0), nil
}

func openAdapter(name string) (WINTUN_ADAPTER_HANDLE, error) {
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	r0, _, e1 := syscall.SyscallN(procWintunOpenAdapter.Addr(), uintptr(unsafe.Pointer(name16)))
	if r0 == 0 {
		return 0, e1
	}
	return WINTUN_ADAPTER_HANDLE(r0), nil
}

func closeAdapter(adapter WINTUN_ADAPTER_HANDLE) {
	syscall.SyscallN(procWintunCloseAdapter.Addr(), uintptr(adapter))
}

func startSession(adapter WINTUN_ADAPTER_HANDLE, capacity uint32) (WINTUN_SESSION_HANDLE, error) {
	r0, _, e1 := syscall.SyscallN(procWintunStartSession.Addr(), uintptr(adapter), uintptr(capacity))
	if r0 == 0 {
		return 0, e1
	}
	return WINTUN_SESSION_HANDLE(r0), nil
}

func endSession(session WINTUN_SESSION_HANDLE) {
	syscall.SyscallN(procWintunEndSession.Addr(), uintptr(session))
}

func getReadWaitEvent(session WINTUN_SESSION_HANDLE) (syscall.Handle, error) {
	r0, _, e1 := syscall.SyscallN(procWintunGetReadWaitEvent.Addr(), uintptr(session))
	if r0 == 0 {
		return 0, e1
	}
	return syscall.Handle(r0), nil
}

func receivePacket(session WINTUN_SESSION_HANDLE) ([]byte, uint32, error) {
	var packetSize uint32
	r0, _, _ := syscall.SyscallN(procWintunReceivePacket.Addr(), uintptr(session), uintptr(unsafe.Pointer(&packetSize)))
	if r0 == 0 {
		return nil, 0, windows.ERROR_NO_MORE_ITEMS
	}
	// r0 is pointer to packet content
	data := unsafe.Slice((*byte)(unsafe.Pointer(r0)), packetSize)
	return data, packetSize, nil
}

func releaseReceivePacket(session WINTUN_SESSION_HANDLE, packetPtr uintptr) {
	syscall.SyscallN(procWintunReleaseReceivePacket.Addr(), uintptr(session), packetPtr)
}

func allocateSendPacket(session WINTUN_SESSION_HANDLE, packetSize uint32) (uintptr, error) {
	r0, _, e1 := syscall.SyscallN(procWintunAllocateSendPacket.Addr(), uintptr(session), uintptr(packetSize))
	if r0 == 0 {
		return 0, e1
	}
	return r0, nil
}

func sendPacket(session WINTUN_SESSION_HANDLE, packetPtr uintptr) {
	syscall.SyscallN(procWintunSendPacket.Addr(), uintptr(session), packetPtr)
}
