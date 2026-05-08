#Requires -RunAsAdministrator
param(
    [string]$Profile = "youtube-discord",
    [int]$RunSecs = 25,
    [string]$Bin = "$PSScriptRoot\dist\sonicdpi.exe"
)

$ErrorActionPreference = "Continue"
$logPath = "$env:LOCALAPPDATA\SonicDPI\sonicdpi.log"

function Sec($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

Sec "ENV"
"date:    $(Get-Date -Format o)"
"profile: $Profile"
"bin:     $Bin (exists=$(Test-Path $Bin))"
"log:     $logPath"
"OS:      $([System.Environment]::OSVersion.VersionString)"

Sec "KILL OLD"
Get-Process sonicdpi,sonicdpi-tray -EA SilentlyContinue | ForEach-Object {
    "stopping pid=$($_.Id) name=$($_.ProcessName)"
    Stop-Process -Id $_.Id -Force -EA SilentlyContinue
}
Start-Sleep 1

Sec "DNS system resolver"
foreach ($h in @("discord.com","gateway.discord.gg","dl.discordapp.net","cdn.discordapp.com","rr1.googlevideo.com")) {
    try {
        $r = Resolve-DnsName -Name $h -Type A -DnsOnly -QuickTimeout -EA Stop |
             Where-Object { $_.IPAddress } | Select-Object -First 3
        "$h -> $($r.IPAddress -join ', ')"
    } catch { "$h -> ERR: $($_.Exception.Message)" }
}

Sec "DNS via Google 8.8.8.8 (compare)"
foreach ($h in @("discord.com","gateway.discord.gg")) {
    try {
        $r = Resolve-DnsName -Name $h -Type A -Server 8.8.8.8 -DnsOnly -QuickTimeout -EA Stop |
             Where-Object { $_.IPAddress } | Select-Object -First 3
        "$h -> $($r.IPAddress -join ', ')"
    } catch { "$h -> ERR: $($_.Exception.Message)" }
}

Sec "TCP connect BEFORE engine"
foreach ($p in @(@("discord.com",443), @("gateway.discord.gg",443), @("dl.discordapp.net",443))) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Test-NetConnection -ComputerName $p[0] -Port $p[1] -WarningAction SilentlyContinue
    $sw.Stop()
    "$($p[0]):$($p[1]) tcp=$($r.TcpTestSucceeded) rtt=$($sw.ElapsedMilliseconds)ms remote=$($r.RemoteAddress)"
}

Sec "TRACERT discord.com 5 hops"
tracert -d -h 5 -w 800 discord.com 2>&1 | Select-Object -First 12

if (-not (Test-Path $Bin)) {
    Write-Host "ERROR: sonicdpi.exe not found at $Bin. Build with cargo build --release or pass -Bin" -ForegroundColor Red
    exit 1
}

Sec "TRUNCATE LOG"
if (Test-Path $logPath) { Clear-Content $logPath; "log cleared" } else { "log not yet exists" }

Sec "SPAWN ENGINE profile=$Profile RunSecs=$RunSecs"
$proc = Start-Process -FilePath $Bin -ArgumentList @("run","--profile",$Profile,"-vv") `
    -PassThru -WindowStyle Hidden
"engine pid=$($proc.Id)"
Start-Sleep 3

if ($proc.HasExited) {
    Write-Host "engine exited immediately! exit code=$($proc.ExitCode)" -ForegroundColor Red
} else {
    "engine alive, running tests..."
}

Sec "DNS WHILE ENGINE RUNNING"
foreach ($h in @("discord.com","gateway.discord.gg","dl.discordapp.net")) {
    try {
        $r = Resolve-DnsName -Name $h -Type A -DnsOnly -QuickTimeout -EA Stop |
             Where-Object { $_.IPAddress } | Select-Object -First 2
        "$h -> $($r.IPAddress -join ', ')"
    } catch { "$h -> ERR" }
}

Sec "HTTPS PROBE WHILE ENGINE RUNNING"
foreach ($u in @(
    "https://discord.com/api/v9/gateway",
    "https://gateway.discord.gg/",
    "https://dl.discordapp.net/distro/app/stable/win/x86/1.0.9189/Discord-1.0.9189-full.nupkg",
    "https://www.youtube.com/",
    "https://rr1.googlevideo.com/"
)) {
    $r = & curl.exe -s -o NUL -w "code=%{http_code} time=%{time_total}s size=%{size_download} ip=%{remote_ip}" `
        --max-time 8 --connect-timeout 5 $u 2>&1
    "{0,-75} {1}" -f $u, $r
}

Sec "SONICDPI PROBE built-in"
& $Bin probe -H gateway.discord.gg -t 3 2>&1 | Select-Object -First 30
"---"
& $Bin probe -H discord.com -t 3 2>&1 | Select-Object -First 30

Sec "WAIT REMAINING"
$elapsed = 6
while ($elapsed -lt $RunSecs -and -not $proc.HasExited) {
    Start-Sleep 2; $elapsed += 2
}

Sec "STOP ENGINE"
if (-not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force -EA SilentlyContinue
    "stopped pid=$($proc.Id)"
} else {
    "engine already exited code=$($proc.ExitCode)"
}
Start-Sleep 1

Sec "LOG WARN ERROR exited"
if (Test-Path $logPath) {
    Select-String -Path $logPath -Pattern "WARN|ERROR|panic|exited|failed" |
        Select-Object -Last 30 | ForEach-Object { $_.Line }
} else { "no log" }

Sec "LOG engine startup"
Select-String -Path $logPath -Pattern "starting engine|WinDivert|filter=" | Select-Object -Last 5 | ForEach-Object { $_.Line }

Sec "LOG classifications by target"
(Get-Content $logPath) | Select-String 'flow classified' |
    ForEach-Object { ($_ -replace '.*target=(\w+).*','$1') } |
    Group-Object | Sort-Object Count -Desc | Format-Table Count,Name -AutoSize

Sec "LOG strategy fires"
(Get-Content $logPath) | Select-String 'strategy fired' |
    ForEach-Object {
        if ($_ -match 'strategy="([^"]+)".*target=Some\((\w+)\)') {
            "$($Matches[1]) -> $($Matches[2])"
        }
    } | Group-Object | Sort-Object Count -Desc | Format-Table Count,Name -AutoSize

Sec "LOG Discord trace last 60"
(Get-Content $logPath) | Select-String 'Discord' | Select-Object -Last 60 | ForEach-Object { $_.Line }

Sec "LOG TTL distribution of fakes"
(Get-Content $logPath) | Select-String 'emit strategy' |
    ForEach-Object {
        if ($_ -match 'strategy="([^"]+)".*ttl=(\S+)') {
            "$($Matches[1]) ttl=$($Matches[2])"
        }
    } | Group-Object | Format-Table Count,Name -AutoSize

Sec "DONE"
"log full path: $logPath"
"log size: $((Get-Item $logPath).Length) bytes"
"copy everything from === ENV === to === DONE === and paste back"
