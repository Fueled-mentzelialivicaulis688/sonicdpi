# SonicDPI — diagnostic harness
#
# Запускать в Admin PowerShell:
#   Set-ExecutionPolicy -Scope Process Bypass; .\scripts\diag.ps1
#
# Скрипт прогоняет все диагностические шаги из docs/diagnostics.md,
# складывает вывод в diag-out\<timestamp>\ и в конце печатает
# короткое резюме «что починить дальше». Пригодно для запуска через
# VS Code AI / Copilot — все артефакты в одной папке.

[CmdletBinding()]
param(
    [string]$Profile  = 'youtube-discord',                # какой профиль engine'у
    [int]   $RunSecs  = 25,                               # сколько секунд держать engine
    [string]$DistDir  = "$PSScriptRoot\..\dist",          # где лежат бинари
    [switch]$SkipBuild,                                   # пропустить cargo build
    [switch]$SkipDns,                                     # пропустить DNS-тесты
    [switch]$KeepProcs                                    # не убивать sonicdpi.exe в начале
)

$ErrorActionPreference = 'Continue'  # один шаг не должен ронять весь harness

# ---- утилиты -------------------------------------------------------------

function Write-Step($name) {
    Write-Host ""
    Write-Host "==== $name ====" -ForegroundColor Cyan
}

function Save-Run($file, [scriptblock]$block) {
    $path = Join-Path $OutDir $file
    & $block 2>&1 | Tee-Object -FilePath $path | Out-Host
    return $path
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "[!] нужны права Admin (WinDivert не загрузится без них)" -ForegroundColor Red
    Write-Host "    запусти PowerShell как админ и повтори" -ForegroundColor Red
    exit 1
}

# ---- подготовка ----------------------------------------------------------

$Repo    = Resolve-Path "$PSScriptRoot\.."
$Stamp   = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$OutDir  = Join-Path $Repo "diag-out\$Stamp"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Set-Location $Repo
Write-Host "[i] repo:    $Repo"
Write-Host "[i] outdir:  $OutDir"
Write-Host "[i] profile: $Profile"

# Engine хост: должен быть запущен в БЕКГРАУНДЕ во время сетевых тестов.
$EngineExe = Join-Path $DistDir 'sonicdpi.exe'
$TrayExe   = Join-Path $DistDir 'sonicdpi-tray.exe'
$EngineLog = Join-Path $OutDir  'engine.log'
$EngineProc = $null

# ---- 1. SANITY: что вообще установлено -----------------------------------

Write-Step '1. sanity: tooling'
Save-Run 'sanity.txt' {
    Write-Output "--- cargo ---"
    & cargo --version
    Write-Output "--- rustc ---"
    & rustc --version
    Write-Output "--- nslookup smoke ---"
    & nslookup -timeout=2 example.com
    Write-Output "--- engine binary ---"
    Get-Item $EngineExe -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime
    Write-Output "--- tray binary ---"
    Get-Item $TrayExe   -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime
} | Out-Null

# ---- 2. KILL OLD PROCS ---------------------------------------------------

if (-not $KeepProcs) {
    Write-Step '2. kill stale sonicdpi processes'
    foreach ($n in 'sonicdpi','sonicdpi-tray','winws') {
        Get-Process -Name $n -ErrorAction SilentlyContinue |
            ForEach-Object { Write-Host "  killing $($_.Name) pid=$($_.Id)"; $_.Kill() }
    }
    Start-Sleep -Seconds 1
}

# ---- 3. BUILD ------------------------------------------------------------

if (-not $SkipBuild) {
    Write-Step '3. cargo build --release --workspace'
    $buildLog = Save-Run 'build.log' {
        & cargo build --release --workspace
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] build failed — see $buildLog" -ForegroundColor Red
        exit 2
    }
    Save-Run 'cargo-test.log' { & cargo test --workspace --lib } | Out-Null

    # синхронизуем dist/ — tray ищет sonicdpi.exe рядом с собой
    Copy-Item "$Repo\target\release\sonicdpi.exe"      "$DistDir\sonicdpi.exe"      -Force
    Copy-Item "$Repo\target\release\sonicdpi-tray.exe" "$DistDir\sonicdpi-tray.exe" -Force
}

# ---- 4. DNS — провайдер vs cloudflare ------------------------------------

if (-not $SkipDns) {
    Write-Step '4. dns resolution check'
    Save-Run 'dns.txt' {
        $hosts = @(
            'discord.com',
            'gateway.discord.gg',
            'cdn.discordapp.com',
            'media.discordapp.net',
            'youtube.com',
            'googlevideo.com',
            'i.ytimg.com'
        )
        foreach ($h in $hosts) {
            Write-Output "--- $h via system resolver ---"
            & nslookup -timeout=3 $h
            Write-Output "--- $h via 1.1.1.1 ---"
            & nslookup -timeout=3 $h 1.1.1.1
        }
    } | Out-Null
}

# ---- 5. TRACERT до CF Discord ----------------------------------------------

Write-Step '5. tracert до CF Discord (нужно для подбора TTL)'
Save-Run 'tracert.txt' {
    & tracert -d -w 2000 -h 12 162.159.137.232
} | Out-Null

# ---- 6. ЗАПУСК ENGINE (в фоне, на $RunSecs секунд) ----------------------

Write-Step "6. start engine in background ($RunSecs s)"
$EngineArgs = @('run','-vv','--log-file', $EngineLog, '--profile', $Profile)
$EngineProc = Start-Process -FilePath $EngineExe -ArgumentList $EngineArgs `
    -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2  # дать WinDivert загрузиться
if ($EngineProc.HasExited) {
    Write-Host "[!] engine упал сразу — admin? WinDivert.dll?" -ForegroundColor Red
    Write-Host "    лог: $EngineLog"
    Get-Content $EngineLog -ErrorAction SilentlyContinue | Out-Host
    exit 3
}
Write-Host "  engine pid=$($EngineProc.Id) → $EngineLog"

# ---- 7. PROBE (полезно для теста classify, не для проверки обхода) -------

Write-Step '7. probe (USERSPACE — engine не задействован)'
Save-Run 'probe.txt' {
    foreach ($h in 'discord.com','gateway.discord.gg','cdn.discordapp.com',
                   'youtube.com','www.googlevideo.com') {
        Write-Output "--- probe -H $h ---"
        & $EngineExe probe -H $h --profiles $Profile
    }
} | Out-Null

# ---- 8. РЕАЛЬНЫЙ ТРАФИК — curl через системный сокет ---------------------

Write-Step '8. real-traffic test (curl через системный TCP, ловится WinDivert)'
Save-Run 'curl.txt' {
    $urls = @(
        'https://discord.com/api/v10/gateway',
        'https://gateway.discord.gg/',
        'https://cdn.discordapp.com/embed/avatars/0.png',
        'https://www.youtube.com/'
    )
    foreach ($u in $urls) {
        Write-Output "--- $u ---"
        & curl.exe -s -o NUL -w "http=%{http_code} time=%{time_total}s connect=%{time_connect}s\n" `
            --max-time 12 $u
    }
} | Out-Null

# ---- 9. ОЖИДАНИЕ И СНЯТИЕ ENGINE ----------------------------------------

Write-Step "9. wait $RunSecs s (открой Discord/YouTube вручную, идёт реальный трафик)"
$remaining = $RunSecs
while ($remaining -gt 0) {
    Start-Sleep -Seconds 1
    $remaining--
    Write-Host -NoNewline "`r  $remaining s left..."
}
Write-Host ""

if (-not $EngineProc.HasExited) {
    Write-Host "  stopping engine pid=$($EngineProc.Id)"
    Stop-Process -Id $EngineProc.Id -Force
}
Start-Sleep -Seconds 1

# ---- 10. АНАЛИЗ ЛОГА ENGINE ---------------------------------------------

Write-Step '10. engine log analysis'
$logSummary = Join-Path $OutDir 'engine-summary.txt'

if (-not (Test-Path $EngineLog)) {
    Write-Host "[!] engine.log пустой/отсутствует" -ForegroundColor Yellow
    "engine.log absent" | Set-Content $logSummary
} else {
    $log = Get-Content $EngineLog
    $strats = $log | Select-String -Pattern 'strategy fired strategy="([^"]+)" target=Some\((\w+)\)' -AllMatches
    $byTarget = @{}
    foreach ($m in $strats.Matches) {
        $strat  = $m.Groups[1].Value
        $target = $m.Groups[2].Value
        $key = "$target / $strat"
        if (-not $byTarget.ContainsKey($key)) { $byTarget[$key] = 0 }
        $byTarget[$key]++
    }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("=== strategies fired (target / name = count) ===")
    foreach ($k in $byTarget.Keys | Sort-Object) {
        [void]$sb.AppendLine("  $k = $($byTarget[$k])")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("=== flow classifications ===")
    $log | Select-String 'flow classified by' |
        Group-Object -Property { $_.Line -replace '.*target=(\w+).*','$1' } |
        Sort-Object Name |
        ForEach-Object { [void]$sb.AppendLine("  $($_.Name) = $($_.Count)") }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("=== TTL distribution (fake packets) ===")
    $log | Select-String 'ttl=Some\((\d+)\)' -AllMatches |
        ForEach-Object { $_.Matches } |
        Group-Object Value |
        Sort-Object Name |
        ForEach-Object { [void]$sb.AppendLine("  $($_.Name) = $($_.Count)") }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("=== first error / warn ===")
    ($log | Select-String -Pattern '\b(WARN|ERROR)\b' | Select-Object -First 5) |
        ForEach-Object { [void]$sb.AppendLine("  $_") }
    $sb.ToString() | Set-Content $logSummary
    Get-Content $logSummary | Out-Host
}

# ---- 11. ИТОГ ------------------------------------------------------------

Write-Step '11. итог'
Write-Host "артефакты: $OutDir" -ForegroundColor Green
Get-ChildItem $OutDir | Format-Table Name, Length, LastWriteTime -AutoSize

Write-Host ""
Write-Host "что смотреть:"
Write-Host "  dns.txt          — резолвится ли discord.com через системный DNS?"
Write-Host "                     если 'не найден' / 0.0.0.0 — DNS-poisoning,"
Write-Host "                     поставь 1.1.1.1 (см. docs/diagnostics.md)"
Write-Host "  tracert.txt      — сколько хопов до CF? TTL fake = (хоп TSPU + 1)"
Write-Host "  curl.txt         — http=000 + time>10s = handshake режется"
Write-Host "                     http=200          = engine пробил"
Write-Host "  engine-summary   — сработали ли strategy fake-multisplit на CF?"
Write-Host "                     если для DiscordCloudflare счёт > 0 а curl"
Write-Host "                     всё равно умер — TSPU stateful, нужна v0.3"
Write-Host "                     мутация real-CH (см. docs/2026-05-status.md)"
