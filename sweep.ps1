#Requires -RunAsAdministrator
# SonicDPI parameter sweep harness.
# Spins up the engine with 50+ different configs, curls Discord/YouTube
# through each, ranks by success+latency, prints the winning TOML.
#
# Run from admin PS:
#   Start-Process powershell -Verb RunAs -ArgumentList '-NoExit','-ExecutionPolicy','Bypass','-File','C:\Users\Sonic\Desktop\SonicDPI\sweep.ps1'
#
# Tweak with -CurlsPerHost / -EngineWarmup / -CurlTimeout / -Quick.

param(
    [int]$CurlsPerHost = 1,
    [int]$EngineWarmup = 2,
    [int]$CurlTimeout = 5,
    [switch]$Quick,                  # smaller matrix, ~3 min
    [string]$Bin = "$PSScriptRoot\dist\sonicdpi.exe",
    [string]$WorkDir = "$PSScriptRoot\.sweep"
)

$ErrorActionPreference = "Continue"
$logPath = "$env:LOCALAPPDATA\SonicDPI\sonicdpi.log"

function Sec($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Stop-Engine {
    Get-Process sonicdpi,sonicdpi-tray -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    Start-Sleep -Milliseconds 800
}

# ---------- target hosts ----------
$TestHosts = @(
    [pscustomobject]@{ name="discord.com";        url="https://discord.com/api/v9/gateway" }
    [pscustomobject]@{ name="gateway.discord.gg"; url="https://gateway.discord.gg/" }
    [pscustomobject]@{ name="dl.discordapp.net";  url="https://dl.discordapp.net/" }
    [pscustomobject]@{ name="www.youtube.com";    url="https://www.youtube.com/" }
)

# ---------- setup ----------
Sec "ENV"
"date:    $(Get-Date -Format o)"
"bin:     $Bin (exists=$(Test-Path $Bin))"
"workdir: $WorkDir"
"hosts:   $($TestHosts.name -join ', ')"
"quick:   $Quick"
if (-not (Test-Path $Bin)) {
    Write-Host "ERROR: build first - cargo build --release" -ForegroundColor Red; exit 1
}
if (-not (Test-Path $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir | Out-Null }

Stop-Engine

# ---------- dump baseline TOML to grab the [targets] section ----------
Sec "DUMP BASELINE"
& $Bin show youtube-discord -o "$WorkDir\base.toml" 2>&1 | Out-Null
if (-not (Test-Path "$WorkDir\base.toml")) {
    Write-Host "ERROR: sonicdpi show failed" -ForegroundColor Red; exit 1
}
$baseToml = Get-Content "$WorkDir\base.toml" -Raw
# extract [targets] block (table + nested arrays-of-tables until next top-level non-targets section)
$lines = $baseToml -split "`r?`n"
$targetsLines = @()
$inTargets = $false
foreach ($ln in $lines) {
    if ($ln -match '^\[(targets|targets\..+|\[targets\..+\])\]') {
        $inTargets = $true
        $targetsLines += $ln
        continue
    }
    if ($ln -match '^\[\[?([a-z_]+)' -and -not ($Matches[1] -like 'targets*')) {
        $inTargets = $false
    }
    if ($inTargets) { $targetsLines += $ln }
}
$targetsBlock = $targetsLines -join "`r`n"
"targets block: $($targetsLines.Count) lines, $($targetsBlock.Length) chars"

# ---------- baseline curl with engine OFF ----------
Sec "PHASE 0 - engine OFF baseline"
$baseline = @{}
foreach ($h in $TestHosts) {
    $r = & curl.exe -s -o NUL -w "%{http_code}|%{time_total}" --max-time $CurlTimeout --connect-timeout 4 $h.url 2>$null
    $p = $r -split '\|'
    $baseline[$h.name] = "$($p[0]) ($($p[1])s)"
    "  $($h.name): $($baseline[$h.name])"
}

# ---------- single config tester ----------
function Test-Config {
    param([string]$Name, [string]$StrategiesToml)
    $tomlPath = "$WorkDir\$Name.toml"
    $full = "name = `"$Name`"`r`n`r`n$targetsBlock`r`n`r`n[strategies]`r`n$StrategiesToml`r`n"
    [System.IO.File]::WriteAllText($tomlPath, $full, [System.Text.Encoding]::UTF8)

    Stop-Engine
    if (Test-Path $logPath) { Clear-Content $logPath -EA SilentlyContinue }
    $proc = Start-Process -FilePath $Bin -ArgumentList @("run","--profile",$tomlPath,"-vv") `
        -PassThru -WindowStyle Hidden
    Start-Sleep $EngineWarmup
    if ($proc.HasExited) {
        return @{ name=$Name; results=@(); engineDied=$true; exitCode=$proc.ExitCode }
    }

    $results = @()
    foreach ($h in $TestHosts) {
        $okCount = 0; $totalTime = 0.0; $codes = @()
        for ($i = 0; $i -lt $CurlsPerHost; $i++) {
            $r = & curl.exe -s -o NUL -w "%{http_code}|%{time_total}" --max-time $CurlTimeout --connect-timeout 4 $h.url 2>$null
            $p = $r -split '\|'
            $code = $p[0]; $t = if ($p[1]) { [double]$p[1] } else { 0.0 }
            $codes += $code
            if ($code -ne "000" -and $code -ne "") { $okCount++; $totalTime += $t }
        }
        $results += [pscustomobject]@{
            host = $h.name
            ok = $okCount
            of = $CurlsPerHost
            avgTime = if ($okCount -gt 0) { [math]::Round($totalTime / $okCount, 2) } else { 0 }
            codes = ($codes -join ',')
        }
    }
    Stop-Engine
    return @{ name=$Name; results=$results; engineDied=$false }
}

# ---------- build the test matrix ----------
$Configs = @()

# Current default (sanity reference)
$Configs += [pscustomobject]@{
    name = "01-default-current"
    toml = @"
[[strategies.host_fake_split]]
fake_host = "www.google.com"
targets = ["YouTube","DiscordGateway"]
repeats = 4
fooling = "ts"

[[strategies.host_fake_split]]
fake_host = "ozon.ru"
targets = ["DiscordCloudflare"]
repeats = 4
fooling = "ts,md5sig"

[strategies.quic_fake_initial]
repeats = 6
decoy_host = "www.google.com"
"@
}

# HostFakeSplit sweep (decoy x fooling x repeats)
$decoys = if ($Quick) { @("ozon.ru","vk.me","www.google.com") } `
                 else { @("ozon.ru","vk.me","max.ru","www.google.com","4pda.to","dzen.ru") }
$foolings = if ($Quick) { @("ts","ts,md5sig") } `
                   else { @("ts","md5sig","ts,md5sig","badseq","ttl=4") }
$repeatsList = if ($Quick) { @(4) } else { @(4,6) }

foreach ($d in $decoys) {
    foreach ($f in $foolings) {
        foreach ($r in $repeatsList) {
            $name = "hfs_${d}_$($f -replace '[,=]','_')_r$r"
            $Configs += [pscustomobject]@{
                name = $name
                toml = @"
[[strategies.host_fake_split]]
fake_host = "$d"
targets = []
repeats = $r
fooling = "$f"

[strategies.quic_fake_initial]
repeats = 6
decoy_host = "www.google.com"
"@
            }
        }
    }
}

# fake_multisplit decoy-only (split_pos=0)
$fmsDecoys = if ($Quick) { @("vk.me","ozon.ru") } else { @("vk.me","max.ru","ozon.ru","4pda.to") }
$fmsFoolings = if ($Quick) { @("ttl=4") } else { @("ttl=4","ts","ts,md5sig") }
foreach ($d in $fmsDecoys) {
    foreach ($f in $fmsFoolings) {
        $name = "fms_${d}_$($f -replace '[,=]','_')_r4"
        $Configs += [pscustomobject]@{
            name = $name
            toml = @"
[[strategies.fake_multisplit]]
fooling = "$f"
repeats = 4
decoy_host = "$d"
split_pos = 0
seqovl = 0
targets = []

[strategies.quic_fake_initial]
repeats = 6
decoy_host = "www.google.com"
"@
        }
    }
}

# fake_multidisorder
$fmdDecoys = if ($Quick) { @("ozon.ru","vk.me") } else { @("ozon.ru","vk.me","max.ru","4pda.to") }
$fmdFoolings = if ($Quick) { @("ts") } else { @("ts","ts,md5sig","badseq") }
foreach ($d in $fmdDecoys) {
    foreach ($f in $fmdFoolings) {
        $name = "fmd_${d}_$($f -replace '[,=]','_')_r4"
        $Configs += [pscustomobject]@{
            name = $name
            toml = @"
[strategies.fake_multidisorder]
fooling = "$f"
repeats = 4
decoy_host = "$d"

[strategies.quic_fake_initial]
repeats = 6
decoy_host = "www.google.com"
"@
        }
    }
}

# tls_multisplit alternates
foreach ($c in @(
    @{n="tlms_568_4pda";   s=568; d="4pda.to"},
    @{n="tlms_681_google"; s=681; d="www.google.com"},
    @{n="tlms_1_google";   s=1;   d="www.google.com"},
    @{n="tlms_1_ozon";     s=1;   d="ozon.ru"}
)) {
    $Configs += [pscustomobject]@{
        name = $c.n
        toml = @"
[[strategies.tls_multisplit]]
split_pos = 1
seqovl = $($c.s)
seqovl_decoy_host = "$($c.d)"
fake_filler_byte = 0
targets = []

[strategies.quic_fake_initial]
repeats = 6
decoy_host = "www.google.com"
"@
    }
}

Sec "TEST PLAN"
"$($Configs.Count) configs x $CurlsPerHost curls x $($TestHosts.Count) hosts = $($Configs.Count * $CurlsPerHost * $TestHosts.Count) trials"
$est = $Configs.Count * ($EngineWarmup + 1 + $TestHosts.Count * 2)
"estimated time: ~$([math]::Round($est/60,1)) min ($est sec)"

# ---------- run sweep ----------
Sec "PHASE 1 - strategy sweep"
$allResults = @()
$i = 0
$startT = Get-Date
foreach ($cfg in $Configs) {
    $i++
    Write-Host -NoNewline ("[{0,3}/{1}] {2,-45} " -f $i, $Configs.Count, $cfg.name)
    $r = Test-Config -Name $cfg.name -StrategiesToml $cfg.toml
    if ($r.engineDied) {
        Write-Host "ENGINE-DIED exit=$($r.exitCode)" -ForegroundColor Red
        continue
    }
    $score = ($r.results | Measure-Object -Property ok -Sum).Sum
    $maxScore = $TestHosts.Count * $CurlsPerHost
    $r['score'] = $score
    $r['maxScore'] = $maxScore
    $r['toml'] = $cfg.toml
    $allResults += $r
    $perHost = ($r.results | ForEach-Object { "$($_.host.Substring(0,[math]::Min(4,$_.host.Length)))=$($_.codes)" }) -join ' '
    $color = if ($score -eq $maxScore) {"Green"} elseif ($score -gt 0) {"Yellow"} else {"DarkGray"}
    Write-Host ("{0,2}/{1}  {2}" -f $score, $maxScore, $perHost) -ForegroundColor $color
}
$elapsed = (Get-Date) - $startT
"sweep done in $([math]::Round($elapsed.TotalSeconds,0))s"

# ---------- rank ----------
Sec "PHASE 2 - top 15 overall (score desc, then avg-latency asc)"
$ranked = $allResults | Where-Object { $_ } | Sort-Object `
    -Property @{e={ -$_.score }}, @{e={
        $okHosts = $_.results | Where-Object { $_.ok -gt 0 }
        if ($okHosts) { ($okHosts | Measure-Object -Property avgTime -Average).Average } else { 999 }
    }}
$ranked | Select-Object -First 15 | ForEach-Object {
    $r = $_
    $hostsStr = ($r.results | ForEach-Object {
        $tag = $_.host.Split('.')[0]
        if ($_.ok -gt 0) { "$tag=$($_.codes)/$($_.avgTime)s" } else { "$tag=FAIL" }
    }) -join ' | '
    $color = if ($r.score -eq $r.maxScore) {"Green"} elseif ($r.score -ge $r.maxScore/2) {"Yellow"} else {"DarkGray"}
    Write-Host ("{0,-50} {1,2}/{2}  {3}" -f $r.name, $r.score, $r.maxScore, $hostsStr) -ForegroundColor $color
}

# ---------- per-host winners ----------
Sec "PHASE 3 - top-3 per host"
foreach ($h in $TestHosts) {
    Write-Host "`n$($h.name):" -ForegroundColor Cyan
    $best = $allResults | ForEach-Object {
        $hr = $_.results | Where-Object { $_.host -eq $h.name } | Select-Object -First 1
        if ($hr) {
            [pscustomobject]@{
                cfg = $_.name
                ok = $hr.ok
                of = $hr.of
                t = $hr.avgTime
                codes = $hr.codes
            }
        }
    } | Sort-Object @{e={-$_.ok}}, @{e={$_.t}} | Select-Object -First 3
    foreach ($b in $best) {
        $col = if ($b.ok -eq $b.of) {"Green"} elseif ($b.ok -gt 0) {"Yellow"} else {"DarkGray"}
        Write-Host ("  {0,-50} {1}/{2}  {3}s  codes={4}" -f $b.cfg,$b.ok,$b.of,$b.t,$b.codes) -ForegroundColor $col
    }
}

# ---------- recommended ----------
Sec "RECOMMENDED CONFIG"
$winner = $ranked | Select-Object -First 1
if ($winner -and $winner.score -gt 0) {
    Write-Host "WINNER: $($winner.name)  ($($winner.score)/$($winner.maxScore))" -ForegroundColor Green
    Write-Host "`n--- TOML (saved to $WorkDir\$($winner.name).toml) ---" -ForegroundColor Cyan
    Get-Content "$WorkDir\$($winner.name).toml" | ForEach-Object { Write-Host $_ }
    Write-Host "`n--- HOW TO APPLY ---" -ForegroundColor Cyan
    Write-Host "Option A - run as-is via CLI:"
    Write-Host "  .\dist\sonicdpi.exe run --profile `"$WorkDir\$($winner.name).toml`" -vv"
    Write-Host "Option B - bake into builtin (edit profile.rs::builtin_youtube_discord)"
} else {
    Write-Host "NO config produced a successful HTTPS handshake. TSPU is blocking at L4 or the engine is not running." -ForegroundColor Red
    Write-Host "Check $logPath for WinDivert open errors or panics."
}

# ---------- log summary ----------
Sec "LOG: WARN/ERROR (last 20)"
if (Test-Path $logPath) {
    Select-String -Path $logPath -Pattern 'WARN|ERROR|panic|exited' | Select-Object -Last 20 | ForEach-Object { $_.Line }
}

Sec "DONE"
"sweep dir:    $WorkDir"
"baseline:     $($baseline | Out-String)"
"copy from === ENV === to === DONE === and paste back"
Stop-Engine
