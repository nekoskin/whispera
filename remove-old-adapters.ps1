# Удаление старых Whispera адаптеров перед созданием нового

Write-Host "Поиск старых Whispera адаптеров..." -ForegroundColor Yellow

$adapters = Get-NetAdapter | Where-Object { 
    $_.Name -like '*whispera*' -or 
    $_.InterfaceDescription -like '*Whispera VPN*' -or
    $_.InterfaceDescription -like '*Meta Tunnel*'
}

if ($adapters) {
    Write-Host "Найдены следующие адаптеры:" -ForegroundColor Yellow
    $adapters | Format-Table Name, InterfaceDescription, Status -AutoSize
    
    Write-Host "`nУдаление старых адаптеров..." -ForegroundColor Yellow
    foreach ($adapter in $adapters) {
        Write-Host "Удаление: $($adapter.Name) ($($adapter.InterfaceDescription))" -ForegroundColor Cyan
        try {
            Remove-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
            Write-Host "  ✓ Удалён успешно" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ Ошибка: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host "`nГотово! Теперь можно запустить клиент заново." -ForegroundColor Green
} else {
    Write-Host "Старые адаптеры не найдены." -ForegroundColor Green
}

