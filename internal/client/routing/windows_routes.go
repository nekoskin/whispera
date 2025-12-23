package routing

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
	
	dnspkg "whispera/internal/dns"
)

var (
	clientDNSServer  *dnspkg.Server
	clientFakeIPPool *dnspkg.FakeIPPool
)

// ConfigureWindowsRoutes настраивает маршруты Windows для перенаправления трафика через TUN интерфейс.
// serverIP используется для исключения сервера из маршрутизации через TUN (чтобы избежать петли).
// tunIP - IP адрес для TUN интерфейса (например, "198.18.0.1")
// tunGateway - виртуальный шлюз для маршрутизации (например, "198.18.0.2")
// tunPrefix - длина префикса подсети (например, 30 для /30)
//
// ВАЖНО: функция делает минимально необходимые шаги:
//  1. Назначает IP tunIP/tunPrefix на интерфейс tunName
//  2. Назначает DNS-сервер tunGateway
//  3. Ставит низкую метрику
//  4. Добавляет host‑route до serverIP (чтобы трафик к серверу не уходил в туннель)
//  5. Добавляет default‑route 0.0.0.0/0 через tunGateway на этот интерфейс.
func ConfigureWindowsRoutes(tunName string, serverIP string, tunIP string, tunGateway string, tunPrefix int) error {
	log.Printf("[INFO] === Windows TUN routing setup for %s ===", tunName)

	var (
		cmd    *exec.Cmd
		output []byte
		err    error
	)

	// --- Попытка 0. Современная автоконфигурация через PowerShell (как в Prizrak/Clash‑подобных клиентах) ---
	// Используем NetTCPIP‑cmdlets:
	//   - ищем адаптер по описанию "*Meta Tunnel*", "*Whispera VPN*" или "*wintun*"
	//   - назначаем tunIP/tunPrefix (по умолчанию 198.18.0.1/30, как у Prizrak-Box/Mihomo)
	//   - назначаем DNS-сервер tunGateway
	//   - ставим metric=1
	//   - добавляем host‑route до serverIP через существующий default‑gateway
	//   - добавляем default‑route 0.0.0.0/0 через tunGateway
	//
	// При любой ошибке НИЧЕГО не меняем в существующих маршрутах и переходим к legacy‑ветке ниже.
	// Вычисляем маску подсети из префикса для netsh
	var subnetMaskStr string
	switch tunPrefix {
	case 30:
		subnetMaskStr = "255.255.255.252"
	case 24:
		subnetMaskStr = "255.255.255.0"
	case 16:
		subnetMaskStr = "255.255.0.0"
	case 8:
		subnetMaskStr = "255.0.0.0"
	default:
		// Вычисляем маску для произвольного префикса
		mask := uint32(0xFFFFFFFF << uint(32-tunPrefix))
		subnetMaskStr = fmt.Sprintf("%d.%d.%d.%d",
			byte(mask>>24), byte(mask>>16), byte(mask>>8), byte(mask))
	}

	psAutoRouting := fmt.Sprintf(`
$ErrorActionPreference = "Stop"
try {
  # Небольшая задержка, чтобы адаптер успел появиться
  Start-Sleep -Milliseconds 800

  # Ищем адаптер Whispera / Wintun (по описанию или имени)
  $adapter = Get-NetAdapter | Where-Object {
    $_.InterfaceDescription -like "*Meta Tunnel*" -or
    $_.InterfaceDescription -like "*Whispera VPN*" -or
    $_.InterfaceDescription -like "*wintun*" -or
    $_.Name -eq "%[1]s" -or
    $_.Name -eq "Whispera"
  } | Sort-Object ifIndex | Select-Object -First 1

  if (-not $adapter) {
    Write-Output "ADAPTER_NOT_FOUND"
    exit 1
  }

  $alias = $adapter.Name
  Write-Output ("[PS-AUTO] Using adapter: " + $alias)

  # Настраиваем профиль подключения, чтобы Windows показывала отдельную сеть
  # с понятным именем (как у Prizrak-Box).
  try {
    $profile = Get-NetConnectionProfile -InterfaceAlias $alias -ErrorAction SilentlyContinue
    if ($profile) {
      Set-NetConnectionProfile -InterfaceAlias $alias -NetworkCategory Private -Name "Whispera" -ErrorAction SilentlyContinue
      Write-Output "[PS-AUTO] Connection profile set to 'Whispera' (Private network)"
    } else {
      Write-Output "[PS-AUTO] WARNING: NetConnectionProfile not found for adapter, skipping profile config"
    }
  } catch {
    Write-Output ("[PS-AUTO] WARNING: Failed to set connection profile: " + $_.Exception.Message)
  }

  # Настраиваем Firewall (разрешаем входящий трафик для TUN)
  try {
    $fwRuleName = "Whispera Inbound Allow"
    # Удаляем старое правило если есть (чтобы обновить параметры)
    Remove-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
    
    # Создаем новое правило для конкретного интерфейса
    New-NetFirewallRule -DisplayName $fwRuleName -InterfaceAlias $alias -Direction Inbound -Action Allow -Profile Any -Protocol Any -ErrorAction SilentlyContinue | Out-Null
    Write-Output "[PS-AUTO] Firewall rule '$fwRuleName' created/updated"
  } catch {
    Write-Output ("[PS-AUTO] WARNING: Failed to set firewall rule: " + $_.Exception.Message)
  }

  # Чистим старые IPv4 адреса
  Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

  # Устанавливаем IP и шлюз одновременно через netsh (критично для отображения шлюза в свойствах TCP/IP)
  # PowerShell New-NetIPAddress не поддерживает -DefaultGateway, поэтому используем netsh
  # Формат: netsh interface ipv4 set address "name" static IP mask gateway metric
  netsh interface ipv4 set address name="$alias" static %[2]s %[3]s %[4]s 1 | Out-Null
  
  # Небольшая задержка, чтобы Windows успел применить изменения
  Start-Sleep -Milliseconds 300
  
  # Назначаем DNS-сервер (ПОСЛЕ назначения IP)
  try {
    Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses "%[4]s" -ErrorAction Stop | Out-Null
    Write-Output "[PS-AUTO] DNS server set to %[4]s"
  } catch {
    Write-Output ("[PS-AUTO] WARNING: Failed to set DNS: " + $_.Exception.Message)
  }

  # Ставим метрику интерфейса (низкая метрика = высокий приоритет)
  try {
    Set-NetIPInterface -InterfaceAlias $alias -InterfaceMetric 1 -ErrorAction Stop | Out-Null
    Write-Output "[PS-AUTO] Interface metric set to 1"
  } catch {
    Write-Output ("[PS-AUTO] WARNING: Failed to set interface metric: " + $_.Exception.Message)
  }
  
  # Чистим старые default‑маршруты через TUN на этом адаптере
  Get-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias $alias -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -eq "%[4]s" } |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

  # Также чистим split‑маршруты 0.0.0.0/1 и 128.0.0.0/1 через TUN
  Get-NetRoute -DestinationPrefix "0.0.0.0/1" -InterfaceAlias $alias -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -eq "%[4]s" } |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  Get-NetRoute -DestinationPrefix "128.0.0.0/1" -InterfaceAlias $alias -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -eq "%[4]s" } |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

  # Определяем основной default‑gateway (не TUN)
  $gwRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.NextHop -ne "%[4]s" -and $_.NextHop -ne '0.0.0.0' } |
    Sort-Object RouteMetric | Select-Object -First 1

  $defaultGW = $null
  if ($gwRoute) {
    $defaultGW = $gwRoute.NextHop
  } else {
    $cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | Select-Object -First 1
    if ($cfg -and $cfg.IPv4DefaultGateway) {
      $defaultGW = $cfg.IPv4DefaultGateway.NextHop
    }
  }

  if ("%[5]s" -ne "" -and $defaultGW) {
    # Host‑route до сервера, чтобы не было петли
    New-NetRoute -DestinationPrefix "%[5]s/32" -NextHop $defaultGW -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null
    Write-Output ("[PS-AUTO] Host route to server %[5]s via " + $defaultGW)
  }

  # Split‑tunnel full‑redirect: вместо одного 0.0.0.0/0 добавляем два маршрута /1.
  # Они всегда приоритетнее любого 0.0.0.0/0 через физический интерфейс, независимо от метрик.
  New-NetRoute -DestinationPrefix "0.0.0.0/1" -InterfaceAlias $alias -NextHop %[4]s -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
  New-NetRoute -DestinationPrefix "128.0.0.0/1" -InterfaceAlias $alias -NextHop %[4]s -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
  Write-Output ("[PS-AUTO] Split default routes 0.0.0.0/1 and 128.0.0.0/1 via %[4]s added")

  Write-Output "SUCCESS"
} catch {
  Write-Output ("[PS-AUTO] ERROR: " + $_.Exception.Message)
  exit 1
}
`, tunName, tunIP, subnetMaskStr, tunGateway, serverIP)

	cmd = exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psAutoRouting)
	output, err = cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(output))
	if err == nil && strings.Contains(outStr, "SUCCESS") {
		log.Printf("[INFO] PowerShell auto-routing completed successfully:\n%s", outStr)
		
		// Небольшая задержка, чтобы IP адрес точно был назначен
		time.Sleep(500 * time.Millisecond)
		
		// Запускаем Fake-IP DNS сервер ПОСЛЕ назначения IP адреса
		if err := startClientDNSServer(tunGateway); err != nil {
			log.Printf("[WARN] Failed to start DNS server: %v (continuing without Fake-IP DNS)", err)
		} else {
			log.Printf("[INFO] ✅ Fake-IP DNS server started on %s:53", tunGateway)
		}
		
		log.Printf("[INFO] === Windows TUN routing (PS auto) completed for %s ===", tunName)
		return nil
	}
	log.Printf("[WARN] PowerShell auto-routing failed (fallback to legacy netsh/route). err=%v, output=\n%s", err, outStr)

	// --- Шаг 0. Назначаем IP tunIP/tunPrefix интерфейсу ---
	log.Printf("[INFO] Assigning %s/%d to TUN interface (PowerShell)...", tunIP, tunPrefix)
	psAssignIP := fmt.Sprintf(
		`$a = Get-NetAdapter -Name "%s" -ErrorAction SilentlyContinue;
		  if ($a) {
			  $ip = Get-NetIPAddress -InterfaceAlias "%s" -AddressFamily IPv4 -ErrorAction SilentlyContinue;
			  if ($ip) { $ip | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
			  New-NetIPAddress -InterfaceAlias "%s" -IPAddress %s -PrefixLength %d -AddressFamily IPv4 -ErrorAction SilentlyContinue | Out-Null;
			  Set-DnsClientServerAddress -InterfaceAlias "%s" -ServerAddresses "%s" -ErrorAction SilentlyContinue | Out-Null;
			  if ($?) { Write-Output "SUCCESS" } else { Write-Output "FAILED" }
		  } else { Write-Output "ADAPTER_NOT_FOUND" }`,
		tunName, tunName, tunName, tunIP, tunPrefix, tunName, tunGateway,
	)
	cmd = exec.Command("powershell", "-Command", psAssignIP)
	output, err = cmd.Output()
	if err != nil {
		log.Printf("[WARN] PowerShell IP assignment failed: %v", err)
	} else {
		log.Printf("[DEBUG] PowerShell IP assignment result: %s", strings.TrimSpace(string(output)))
	}

	// Резерв: netsh, если PowerShell не смог
	// ВАЖНО: имя интерфейса может содержать пробелы и # (например "Whispera VPN Tunnel #2"),
	// поэтому всегда оборачиваем его в кавычки внутри аргумента (name="...").
	// Вычисляем маску подсети из префикса для netsh
	var subnetMask string
	switch tunPrefix {
	case 30:
		subnetMask = "255.255.255.252"
	case 24:
		subnetMask = "255.255.255.0"
	case 16:
		subnetMask = "255.255.0.0"
	case 8:
		subnetMask = "255.0.0.0"
	default:
		// Вычисляем маску для произвольного префикса
		mask := uint32(0xFFFFFFFF << uint(32-tunPrefix))
		subnetMask = fmt.Sprintf("%d.%d.%d.%d",
			byte(mask>>24), byte(mask>>16), byte(mask>>8), byte(mask))
	}

	quotedName := fmt.Sprintf("name=%q", tunName)
	cmd = exec.Command("netsh", "interface", "ipv4", "set", "address",
		quotedName, "static", tunIP, subnetMask)
	if err = cmd.Run(); err != nil {
		log.Printf("[WARN] netsh set address failed: %v, trying add...", err)
		cmd = exec.Command("netsh", "interface", "ipv4", "add", "address",
			quotedName, fmt.Sprintf("address=%s", tunIP), fmt.Sprintf("mask=%s", subnetMask))
		if err = cmd.Run(); err != nil {
			return fmt.Errorf("failed to assign IP %s/%d to %s: %w", tunIP, tunPrefix, tunName, err)
		}
	}

	// Назначаем DNS через netsh
	log.Printf("[INFO] Setting DNS to %s for %s...", tunGateway, tunName)
	cmd = exec.Command("netsh", "interface", "ipv4", "set", "dns",
		quotedName, "static", tunGateway, "validate=no")
	if err := cmd.Run(); err != nil {
		log.Printf("[WARN] Failed to set DNS to %s: %v. Trying 8.8.8.8...", tunGateway, err)
		// Try fallback
		cmd = exec.Command("netsh", "interface", "ipv4", "set", "dns",
			quotedName, "static", "8.8.8.8", "validate=no")
		if err := cmd.Run(); err != nil {
			log.Printf("[ERROR] Failed to set fallback DNS: %v", err)
		} else {
			log.Printf("[INFO] Fallback DNS 8.8.8.8 set successfully")
		}
	} else {
		log.Printf("[INFO] DNS set to %s successfully", tunGateway)
	}

	// Проверяем, что IP действительно назначен (с несколькими попытками)
	var ipFound bool
	for i := 0; i < 3; i++ {
		time.Sleep(500 * time.Millisecond)
		cmd = exec.Command("netsh", "interface", "ipv4", "show", "addresses", quotedName)
		if output, err = cmd.Output(); err == nil {
			out := string(output)
			log.Printf("[DEBUG] TUN IPv4 info (attempt %d/3):\n%s", i+1, out)
			if strings.Contains(out, tunIP) {
				ipFound = true
				log.Printf("[INFO] ✅ IP address %s confirmed on interface %s", tunIP, tunName)
				break
			}
		} else {
			log.Printf("[WARN] Could not verify IP assignment (attempt %d/3): %v", i+1, err)
		}
	}
	if !ipFound {
		log.Printf("[WARN] IP %s not found on interface %s after 3 attempts (continuing anyway)", tunIP, tunName)
		// Не возвращаем ошибку, продолжаем работу
	}

	// --- Шаг 1. Ставим минимальную метрику ---
	ifMetric := fmt.Sprintf("interface=%q", tunName)
	cmd = exec.Command("netsh", "interface", "ipv4", "set", "interface",
		ifMetric, "metric=1")
	if err = cmd.Run(); err != nil {
		log.Printf("[WARN] Failed to set interface metric=1 for %s: %v", tunName, err)
	}

	// --- Шаг 2. Узнаём индекс интерфейса (ifIndex) ---
	// Используем PowerShell для более надежного получения индекса
	psGetIndex := fmt.Sprintf(`
$adapter = Get-NetAdapter | Where-Object {
    $_.Name -eq "%s" -or
    $_.InterfaceDescription -like "*Meta Tunnel*" -or
    $_.InterfaceDescription -like "*wintun*"
} | Sort-Object ifIndex | Select-Object -First 1
if ($adapter) {
    Write-Output $adapter.ifIndex
} else {
    Write-Output "NOT_FOUND"
    exit 1
}
`, tunName)
	cmd = exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psGetIndex)
	output, err = cmd.Output()
	var ifIndex string
	if err == nil {
		ifIndex = strings.TrimSpace(string(output))
		if ifIndex == "NOT_FOUND" || ifIndex == "" {
			// Fallback к netsh
			cmd = exec.Command("netsh", "interface", "ipv4", "show", "interface", ifMetric)
			output, err = cmd.Output()
			if err == nil {
				for _, line := range strings.Split(string(output), "\n") {
					if strings.Contains(line, tunName) || strings.Contains(line, "Meta Tunnel") {
						fields := strings.Fields(line)
						// Ищем первое число в строке (это индекс)
						for _, f := range fields {
							if _, err := strconv.Atoi(f); err == nil {
								ifIndex = f
								break
							}
						}
						if ifIndex != "" {
							break
						}
					}
				}
			}
		}
	}
	if ifIndex == "" {
		return fmt.Errorf("could not parse interface index for %s", tunName)
	}
	log.Printf("[INFO] TUN interface index: %s", ifIndex)
	
	// Небольшая задержка, чтобы IP адрес точно был назначен
	time.Sleep(1 * time.Second) // Увеличена задержка для надежности
	
	// Запускаем Fake-IP DNS сервер ПОСЛЕ назначения IP адреса
	// DNS сервер слушает на 0.0.0.0:53, но Windows настроен отправлять запросы на tunGateway (198.18.0.2:53)
	log.Printf("[INFO] Starting Fake-IP DNS server on 0.0.0.0:53 (Windows DNS configured to %s:53)...", tunGateway)
	if err := startClientDNSServer(tunGateway); err != nil {
		log.Printf("[WARN] Failed to start DNS server: %v (continuing without Fake-IP DNS)", err)
	} else {
		log.Printf("[INFO] ✅ Fake-IP DNS server started on 0.0.0.0:53 (Windows DNS: %s:53)", tunGateway)
	}

	// --- Шаг 3. Host‑route до serverIP (чтобы не было петли) ---
	if serverIP != "" && net.ParseIP(serverIP) != nil {
		log.Printf("[INFO] Ensuring direct route to VPN server %s (bypass TUN)...", serverIP)

		cmd = exec.Command("route", "print", "0.0.0.0")
		output, err = cmd.Output()
		if err != nil {
			log.Printf("[WARN] route print failed: %v", err)
		}
		var defaultGateway string
		for _, line := range strings.Split(string(output), "\n") {
			if strings.Contains(line, "0.0.0.0") &&
				strings.Contains(line, "0.0.0.0") &&
				!strings.Contains(line, "On-link") {
				fields := strings.Fields(line)
				for _, f := range fields {
					if ip := net.ParseIP(f); ip != nil && f != "0.0.0.0" {
						defaultGateway = f
						break
					}
				}
				if defaultGateway != "" {
					break
				}
			}
		}

		if defaultGateway != "" {
			cmd = exec.Command("route", "add", serverIP, "mask", "255.255.255.255",
				defaultGateway, "metric", "1")
			if err = cmd.Run(); err != nil {
				log.Printf("[DEBUG] route add %s via %s failed (maybe exists): %v",
					serverIP, defaultGateway, err)
			} else {
				log.Printf("[INFO] ✅ Direct route to server %s via %s added", serverIP, defaultGateway)
			}
		} else {
			log.Printf("[WARN] Could not determine default gateway – skipping server host‑route")
		}
	}

	// --- Шаг 4. Split default routes через tunGateway на TUN ---
	//
	// Вместо одного 0.0.0.0/0 добавляем два маршрута /1:
	//   0.0.0.0/1   -> tunGateway
	//   128.0.0.0/1 -> tunGateway
	// Они всегда приоритетнее любого 0.0.0.0/0 через физический интерфейс,
	// независимо от метрик, но при этом не ломают системный default‑route.
	log.Printf("[INFO] Configuring split default routes 0.0.0.0/1 and 128.0.0.0/1 via %s on %s (ifIndex=%s) without deleting existing default routes...",
		tunGateway, tunName, ifIndex)

	// Пытаемся добавить маршруты через netsh (предпочтительный способ)
	splitPrefixes := []struct {
		Prefix string
		Net    string
		Mask   string
	}{
		{"0.0.0.0/1", "0.0.0.0", "128.0.0.0"},
		{"128.0.0.0/1", "128.0.0.0", "128.0.0.0"},
	}

	for _, p := range splitPrefixes {
		// Сначала пробуем через route.exe с явным указанием интерфейса (более надежно)
		cmd = exec.Command("route", "add", p.Net, "mask", p.Mask,
			tunGateway, "metric", "1", "if", ifIndex)
		if err = cmd.Run(); err != nil {
			log.Printf("[WARN] route.exe add %s via %s (if=%s) failed: %v, trying netsh...", p.Prefix, tunGateway, ifIndex, err)
			// Fallback: netsh
			cmd = exec.Command("netsh", "interface", "ipv4", "add", "route",
				p.Prefix, tunName, tunGateway, "metric=1", "store=active")
			if err = cmd.Run(); err != nil {
				log.Printf("[ERROR] Failed to add split default route %s via %s (ifIndex=%s): %v", p.Prefix, tunGateway, ifIndex, err)
				// Не возвращаем ошибку, продолжаем работу
			} else {
				log.Printf("[INFO] ✅ Added route %s via %s on %s (ifIndex=%s)", p.Prefix, tunGateway, tunName, ifIndex)
			}
		} else {
			log.Printf("[INFO] ✅ Added route %s via %s (ifIndex=%s)", p.Prefix, tunGateway, ifIndex)
		}
	}

	// Проверка default‑route
	cmd = exec.Command("route", "print", "0.0.0.0")
	if output, err = cmd.Output(); err == nil {
		out := string(output)
		log.Printf("[DEBUG] Default route table:\n%s", out)
		if !strings.Contains(out, ifIndex) && !strings.Contains(out, tunName) {
			log.Printf("[WARN] Default route exists but does not reference %s (index %s)", tunName, ifIndex)
		} else {
			log.Printf("[INFO] ✅ Verified: default route through TUN is active")
		}
	} else {
		log.Printf("[WARN] Could not verify default route: %v", err)
	}

	// --- Шаг 5. Настраиваем профиль подключения, чтобы Windows показывала отдельную сеть "Whispera". ---
	psSetProfile := fmt.Sprintf(
		`$ErrorActionPreference = "SilentlyContinue";
		  try {
		    $profile = Get-NetConnectionProfile -InterfaceAlias "%s" -ErrorAction SilentlyContinue;
		    if ($profile) {
		      Set-NetConnectionProfile -InterfaceAlias "%s" -NetworkCategory Private -Name "Whispera" -ErrorAction SilentlyContinue | Out-Null;
		      Write-Output "PROFILE_OK";
		    } else {
		      Write-Output "PROFILE_MISSING";
		    }
		  } catch {
		    Write-Output ("PROFILE_ERR: " + $_.Exception.Message);
		  }`,
		tunName, tunName,
	)
	cmd = exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psSetProfile)
	if output, err = cmd.Output(); err != nil {
		log.Printf("[WARN] Failed to configure Windows connection profile for %s: %v", tunName, err)
	} else {
		log.Printf("[DEBUG] Connection profile setup result for %s: %s", tunName, strings.TrimSpace(string(output)))
	}

	log.Printf("[INFO] === Windows TUN routing setup completed for %s ===", tunName)
	log.Printf("[INFO] ⚠️  Run client as Administrator; otherwise netsh/route commands may silently fail")
	return nil
}

// startClientDNSServer запускает Fake-IP DNS сервер на клиенте
func startClientDNSServer(tunGateway string) error {
	if clientFakeIPPool == nil {
		clientFakeIPPool = dnspkg.NewFakeIPPool()
		log.Printf("[DNS] Created Fake-IP pool for client")
	}

	// Если DNS сервер уже запущен, не запускаем повторно
	if clientDNSServer != nil {
		return nil
	}

	// КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: DNS сервер должен слушать на tunGateway:53, а не на 0.0.0.0:53
	// Windows настроен отправлять DNS запросы на tunGateway (198.18.0.2:53)
	// DNS запросы будут приходить через TUN интерфейс как UDP пакеты на 198.18.0.2:53
	// Поэтому сервер должен слушать на tunGateway:53, чтобы перехватывать эти запросы
	dnsAddr := tunGateway + ":53"
	log.Printf("[DNS] Starting Fake-IP DNS server on %s (Windows DNS configured to %s:53)", dnsAddr, tunGateway)
	clientDNSServer = dnspkg.NewServer(dnsAddr, clientFakeIPPool)
	
	// КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Также слушаем на 127.0.0.1:53 для локальных запросов
	// Это нужно для случаев, когда приложения используют localhost для DNS
	localDNSAddr := "127.0.0.1:53"
	localDNSServer := dnspkg.NewServer(localDNSAddr, clientFakeIPPool)
	
	if err := clientDNSServer.Start(); err != nil {
		log.Printf("[DNS] WARN: Failed to start DNS server on %s: %v (trying localhost)", dnsAddr, err)
		// Пробуем запустить на localhost как fallback
		if err2 := localDNSServer.Start(); err2 != nil {
			return fmt.Errorf("failed to start DNS server on both %s and %s: %v, %v", dnsAddr, localDNSAddr, err, err2)
		}
		log.Printf("[DNS] ✅ Fake-IP DNS server started on %s (fallback)", localDNSAddr)
		return nil
	}
	
	// Запускаем также на localhost для надежности
	go func() {
		if err := localDNSServer.Start(); err != nil {
			log.Printf("[DNS] WARN: Failed to start localhost DNS server: %v", err)
		} else {
			log.Printf("[DNS] ✅ Fake-IP DNS server also started on %s", localDNSAddr)
		}
	}()
	
	log.Printf("[DNS] ✅ Fake-IP DNS server started on %s", dnsAddr)
	return nil
}

// GetClientFakeIPPool возвращает FakeIPPool клиента (для синхронизации с сервером)
func GetClientFakeIPPool() *dnspkg.FakeIPPool {
	return clientFakeIPPool
}

