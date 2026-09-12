# Auto-installer for Npcap (Windows packet capture driver for KeenGuard / Scapy)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  KeenGuard: Автоматическая установка драйвера Npcap     " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# Check if already installed
$wpcapDll = Join-Path $env:SystemRoot "System32\wpcap.dll"
$npcapDir = Join-Path $env:SystemRoot "System32\Npcap"
if ((Test-Path $wpcapDll) -or (Test-Path $npcapDir)) {
    Write-Host "[OK] Npcap уже установлен в системе!" -ForegroundColor Green
    Write-Host "  Расположение: $npcapDir" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Вы можете сразу запускать start.bat." -ForegroundColor White
    exit 0
}

# Ensure Admin elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[INFO] Запрос прав Администратора для установки сетевого драйвера NDIS..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Definition
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
    exit 0
}

$tempFile = Join-Path $env:TEMP "npcap-setup.exe"

try {
    Write-Host "[1/3] Поиск актуальной версии Npcap на npcap.com..." -ForegroundColor Cyan
    $downloadUrl = "https://npcap.com/dist/npcap-1.88.exe"
    try {
        $html = (Invoke-WebRequest -Uri "https://npcap.com/#download" -UseBasicParsing -TimeoutSec 10).Content
        if ($html -match 'dist/(npcap-[0-9.]+\.exe)') {
            $downloadUrl = "https://npcap.com/dist/" + $matches[1]
        }
    } catch {
        Write-Host "  (Используется ссылка по умолчанию: $downloadUrl)" -ForegroundColor Gray
    }

    Write-Host "[2/3] Скачивание инсталлятора ($downloadUrl)..." -ForegroundColor Cyan
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -UseBasicParsing
    $fileSizeKb = [math]::Round((Get-Item $tempFile).Length / 1024)
    Write-Host "  Успешно скачано: $fileSizeKb KB" -ForegroundColor Green

    Write-Host "[3/3] Запуск инсталлятора Npcap с параметром /winpcap_mode=yes..." -ForegroundColor Cyan
    Write-Host "  (Подтвердите установку в появившемся окне инсталлятора)" -ForegroundColor Gray

    # /winpcap_mode=yes installs wpcap.dll and Packet.dll in System32 for Scapy compatibility
    $process = Start-Process -FilePath $tempFile -ArgumentList "/winpcap_mode=yes" -Wait -PassThru

    Write-Host ""
    if ((Test-Path $wpcapDll) -or (Test-Path $npcapDir)) {
        Write-Host "========================================================" -ForegroundColor Green
        Write-Host "  [УСПЕХ] Драйвер Npcap успешно установлен!" -ForegroundColor Green
        Write-Host "  Теперь Scapy имеет прямой доступ к L2-пакетам." -ForegroundColor Green
        Write-Host "========================================================" -ForegroundColor Green
    } else {
        Write-Host "[INFO] Процесс установки завершен (код: $($process.ExitCode))." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[ОШИБКА] Не удалось выполнить установку: $_" -ForegroundColor Red
} finally {
    if (Test-Path $tempFile) {
        Remove-Item -Force $tempFile -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "Нажмите любую клавишу для завершения..."
try {
    [Console]::ReadKey($true) | Out-Null
} catch {
    # If stdin not interactive
    Start-Sleep -Seconds 3
}
