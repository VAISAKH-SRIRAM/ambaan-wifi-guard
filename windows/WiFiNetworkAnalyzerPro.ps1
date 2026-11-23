# Wi-Fi Network Analyzer Pro - Windows 11
# PowerShell 5.1+. Local diagnostics, history, dashboard and opt-in repairs.
# No third-party modules required. Speed test uses Cloudflare public endpoints (~25 MB/run).

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Reports = Join-Path $Root "Reports"
$History = Join-Path $Root "History"
New-Item -ItemType Directory -Force -Path $Reports,$History | Out-Null
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Now = Get-Date
$Csv = Join-Path $History "NetworkHistory.csv"
$HtmlReport = Join-Path $Reports "WiFiDashboard-$Stamp.html"
$TxtReport = Join-Path $Reports "WiFiReport-$Stamp.txt"
$Results = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param([string]$Area,[string]$Check,[string]$Value,[string]$Status,[string]$Explanation="")
    $Results.Add([pscustomobject]@{Area=$Area;Check=$Check;Value=$Value;Status=$Status;Explanation=$Explanation}) | Out-Null
    $color = switch ($Status) { "PASS" {"Green"} "WARNING" {"Yellow"} "FAIL" {"Red"} default {"Gray"} }
    Write-Host ("{0,-22} {1,-24} {2}" -f $Check,$Value,$Status) -ForegroundColor $color
    if ($Explanation) { Write-Host "  $Explanation" -ForegroundColor DarkGray }
}
function Ping-Target {
    param([string]$Target,[int]$Count=15)
    $p = New-Object System.Net.NetworkInformation.Ping
    $times = @(); $lost = 0
    for($i=0;$i -lt $Count;$i++){
        try {
            $r=$p.Send($Target,1800)
            if($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success){$times += [double]$r.RoundtripTime}else{$lost++}
        } catch {$lost++}
        Start-Sleep -Milliseconds 100
    }
    $p.Dispose()
    [pscustomobject]@{
        Sent=$Count;Received=$times.Count;Loss=[math]::Round(($lost/$Count)*100,1)
        Avg=if($times.Count){[math]::Round(($times|Measure-Object -Average).Average,1)}else{$null}
        Min=if($times.Count){($times|Measure-Object -Minimum).Minimum}else{$null}
        Max=if($times.Count){($times|Measure-Object -Maximum).Maximum}else{$null}
    }
}
function Run-SpeedTest {
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [TimeSpan]::FromSeconds(60)
    $down=$null; $up=$null; $downErr=""; $upErr=""
    try {
        $n=20000000
        $url="https://speed.cloudflare.com/__down?bytes=$n&x=$([guid]::NewGuid().ToString('N'))"
        $sw=[Diagnostics.Stopwatch]::StartNew()
        $resp=$client.GetAsync($url,[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        $resp.EnsureSuccessStatusCode()
        $stream=$resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $buf=New-Object byte[] 65536; [long]$total=0
        while(($read=$stream.Read($buf,0,$buf.Length)) -gt 0){$total += $read}
        $stream.Dispose();$resp.Dispose();$sw.Stop()
        if($sw.Elapsed.TotalSeconds -gt 0){$down=[math]::Round(($total*8/1000000)/$sw.Elapsed.TotalSeconds,1)}
    } catch {$downErr=$_.Exception.Message}
    try {
        $n=5000000; $payload=New-Object byte[] $n
        $rng=[Security.Cryptography.RandomNumberGenerator]::Create();$rng.GetBytes($payload);$rng.Dispose()
        $content=New-Object System.Net.Http.ByteArrayContent(,$payload)
        $content.Headers.ContentType=[Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/octet-stream")
        $sw=[Diagnostics.Stopwatch]::StartNew()
        $resp=$client.PostAsync("https://speed.cloudflare.com/__up",$content).GetAwaiter().GetResult()
        $resp.EnsureSuccessStatusCode();$null=$resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $resp.Dispose();$content.Dispose();$sw.Stop()
        if($sw.Elapsed.TotalSeconds -gt 0){$up=[math]::Round(($n*8/1000000)/$sw.Elapsed.TotalSeconds,1)}
    } catch {$upErr=$_.Exception.Message}
    $client.Dispose()
    [pscustomobject]@{Download=$down;Upload=$up;DownloadError=$downErr;UploadError=$upErr}
}
function HtmlEncode([object]$x){[System.Net.WebUtility]::HtmlEncode([string]$x)}

Write-Host "`n=== WI-FI NETWORK ANALYZER PRO ===" -ForegroundColor Cyan
Write-Host "Started: $($Now.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "Speed test transfers approximately 25 MB. Press Ctrl+C to cancel.`n" -ForegroundColor DarkYellow

# Active Wi-Fi adapter and current link details
$wifiText = (netsh wlan show interfaces) -join "`n"
function Parse-Netsh([string]$label) {
    $m=[regex]::Match($wifiText,"(?im)^\s*$label\s*:\s*(.+?)\s*$")
    if($m.Success){$m.Groups[1].Value.Trim()}else{$null}
}
$connected = $wifiText -match '(?im)^\s*State\s*:\s*connected'
$wifiName=Parse-Netsh "Name"; $ssid=Parse-Netsh "SSID"; $band=Parse-Netsh "Band"
$channel=Parse-Netsh "Channel"; $radio=Parse-Netsh "Radio type"
$sigText=Parse-Netsh "Signal";$rssiText=Parse-Netsh "Rssi"
$rxText=Parse-Netsh "Receive rate \(Mbps\)";$txText=Parse-Netsh "Transmit rate \(Mbps\)"
$signal=$null;$rssi=$null;$rx=$null;$tx=$null
if($sigText -match '(\d+)'){$signal=[int]$Matches[1]}
if($rssiText -match '-?\d+'){$rssi=[int]$Matches[0]}
if($rxText -match '([\d.]+)'){$rx=[double]$Matches[1]}
if($txText -match '([\d.]+)'){$tx=[double]$Matches[1]}
Add-Check "Wi-Fi" "Connection" $(if($connected){"Connected"}else{"Disconnected"}) $(if($connected){"PASS"}else{"FAIL"})
if($null -ne $signal){Add-Check "Wi-Fi" "Signal strength" "$signal%" $(if($signal -ge 80){"PASS"}elseif($signal -ge 50){"WARNING"}else{"FAIL"})}
if($null -ne $rssi){Add-Check "Wi-Fi" "RSSI" "$rssi dBm" $(if($rssi -ge -60){"PASS"}elseif($rssi -ge -70){"WARNING"}else{"FAIL"}) "Closer to zero is stronger."}
Add-Check "Wi-Fi" "Band / channel" "$band / $channel" "INFO" "Radio type: $radio"
Add-Check "Wi-Fi" "Link rate" "RX $rx / TX $tx Mbps" "INFO" "PHY link rate is not real internet throughput."

# Active default gateway
$ipcfg=Get-NetIPConfiguration | Where-Object {$_.NetAdapter.Status -eq "Up" -and $_.IPv4DefaultGateway} | Select-Object -First 1
$gateway=$null
if($ipcfg){$gateway=$ipcfg.IPv4DefaultGateway.NextHop}
$router=$null
if($gateway){
    Write-Host "`nTesting local router..." -ForegroundColor Cyan
    $router=Ping-Target $gateway 20
    $st=if($router.Loss -gt 5 -or ($router.Avg -ne $null -and $router.Avg -gt 20)){"FAIL"}elseif($router.Loss -gt 0 -or ($router.Avg -ne $null -and $router.Avg -gt 5)){"WARNING"}else{"PASS"}
    Add-Check "Local network" "Router latency" "$(if($null -ne $router.Avg){"$($router.Avg) ms avg"}else{"No replies"})" $st "$($router.Loss)% packet loss; router address hidden from report."
}else{Add-Check "Local network" "Default gateway" "Not found" "FAIL" "No active IPv4 gateway was found."}

# Internet endpoints
Write-Host "`nTesting internet endpoints..." -ForegroundColor Cyan
$pingCloud=Ping-Target "1.1.1.1" 20
$pingGoogle=Ping-Target "8.8.8.8" 20
foreach($entry in @(@{Name="Cloudflare 1.1.1.1";P=$pingCloud},@{Name="Google 8.8.8.8";P=$pingGoogle})){
    $p=$entry.P
    $st=if($p.Loss -gt 5 -or ($p.Avg -ne $null -and $p.Avg -gt 150)){"FAIL"}elseif($p.Loss -gt 0 -or ($p.Avg -ne $null -and $p.Avg -gt 80)){"WARNING"}elseif($null -eq $p.Avg){"FAIL"}else{"PASS"}
    Add-Check "Internet" $entry.Name "$(if($null -ne $p.Avg){"$($p.Avg) ms avg"}else{"No replies"})" $st "$($p.Loss)% loss; min $($p.Min) / max $($p.Max) ms."
}

# DNS lookup timing
Write-Host "`nTesting DNS..." -ForegroundColor Cyan
$dnsMs=$null;$dnsStatus="Failed"
try {
    $sw=[Diagnostics.Stopwatch]::StartNew()
    $null=Resolve-DnsName "www.microsoft.com" -Type A -DnsOnly -ErrorAction Stop
    $sw.Stop();$dnsMs=[math]::Round($sw.Elapsed.TotalMilliseconds,1);$dnsStatus="Working"
    Add-Check "DNS" "Lookup time" "$dnsMs ms" $(if($dnsMs -lt 100){"PASS"}elseif($dnsMs -lt 300){"WARNING"}else{"FAIL"}) "One lookup; DNS caching can affect this measurement."
}catch{Add-Check "DNS" "Resolution" "Failed" "FAIL" "Could not resolve www.microsoft.com."}

# DNS safety (V5): dead/typo servers and scam-link filtering
Write-Host "`nChecking DNS safety..." -ForegroundColor Cyan
. (Join-Path $Root "NetSafety.ps1")
$dnsSafe = Get-DnsSafety
foreach ($srv in $dnsSafe.Servers) {
    $shown = if ($srv.Kind -eq 'Router') { 'Router (local)' } else { $srv.Address }
    $val = if ($srv.Unused) { 'Unused (no IPv6)' } elseif ($srv.Responds) { "Answers in $($srv.Ms) ms" } else { 'NOT ANSWERING' }
    $st = if ($srv.Unused) { 'INFO' } elseif (-not $srv.Responds) { 'FAIL' } elseif ($srv.Kind -eq 'Filter') { 'PASS' } else { 'INFO' }
    $exp = $srv.Label + $(if ($srv.Typo) { ". Looks like a typo: did you mean $($srv.Typo)?" } else { '' })
    Add-Check "DNS safety" "Server $shown" $val $st $exp
}
$shieldStatus = switch ($dnsSafe.Shield) { 'On' { 'PASS' } 'Partial' { 'WARNING' } 'Off' { 'WARNING' } default { 'INFO' } }
Add-Check "DNS safety" "Scam-link filter" $dnsSafe.Shield $shieldStatus "$($dnsSafe.Detail) To protect every device at home, set 1.1.1.2 / 1.0.0.2 as DNS on the router."

# Route path - hop results are best effort, routers may not respond to TTL probes
Write-Host "`nTracing route to 1.1.1.1 (best effort)..." -ForegroundColor Cyan
$routeLines=@()
try {
    $tr=tracert.exe -d -h 12 -w 900 1.1.1.1 2>&1
    $routeLines=@($tr | Select-Object -Skip 1 | Select-Object -First 12 | ForEach-Object {[string]$_})
    $reachableHops=@($routeLines | Where-Object {$_ -match '\d+\.\d+\.\d+\.\d+'}).Count
    Add-Check "Routing" "Traceroute" "$reachableHops responding hops" "INFO" "Non-responding hops are common; this alone does not prove packet loss."
}catch{Add-Check "Routing" "Traceroute" "Unavailable" "INFO" "Could not run tracert."}

# Nearby Wi-Fi scan (names and BSSIDs intentionally not stored in reports)
Write-Host "`nScanning nearby Wi-Fi networks..." -ForegroundColor Cyan
$scanText=(netsh wlan show networks mode=bssid) -join "`n"
$networkCount=([regex]::Matches($scanText,'(?im)^\s*SSID\s+\d+\s*:')).Count
$channelCounts=@{}
foreach($m in [regex]::Matches($scanText,'(?im)^\s*Channel\s*:\s*(\d+)')){
    $ch=$m.Groups[1].Value
    if(!$channelCounts.ContainsKey($ch)){$channelCounts[$ch]=0}
    $channelCounts[$ch]++
}
$busyChannels=($channelCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3 | ForEach-Object {"CH $($_.Key): $($_.Value)"}) -join ", "
Add-Check "Wi-Fi environment" "Nearby networks" "$networkCount detected" "INFO" "Channel counts: $(if($busyChannels){$busyChannels}else{'Not available'}). Scan is a snapshot, not a full RF spectrum analysis."

# Speed test
Write-Host "`nRunning automatic speed test via Cloudflare (~25 MB)..." -ForegroundColor Cyan
$speed=Run-SpeedTest
$down=$speed.Download;$up=$speed.Upload
if($null -ne $down){Add-Check "Throughput" "Download" "$down Mbps" $(if($down -ge 50){"PASS"}elseif($down -ge 10){"WARNING"}else{"FAIL"}) "Compare against your subscribed plan; server conditions affect results."}
else{Add-Check "Throughput" "Download" "Unavailable" "WARNING" $speed.DownloadError}
if($null -ne $up){Add-Check "Throughput" "Upload" "$up Mbps" $(if($up -ge 10){"PASS"}elseif($up -ge 2){"WARNING"}else{"FAIL"})}
else{Add-Check "Throughput" "Upload" "Unavailable" "WARNING" $speed.UploadError}

# Aggregate adapter bytes for machine-level usage snapshot
$adapterStats=$null
try {
    $adapterStats=Get-NetAdapterStatistics -Name $wifiName
    if($adapterStats){Add-Check "Adapter" "Cumulative bytes" ("RX {0:N0} / TX {1:N0}" -f $adapterStats.ReceivedBytes,$adapterStats.SentBytes) "INFO" "Counters are cumulative since adapter start; not per-app usage."}
}catch{}

# Monitored Servers & Services Health Checks
Write-Host "`nTesting monitored servers and services..." -ForegroundColor Cyan
$serverScript = Join-Path $Root "ServerMonitor.ps1"
$intelScript = Join-Path $Root "NetworkIntelligence.ps1"
$topoScript = Join-Path $Root "TopologyEngine.ps1"
if (Test-Path $serverScript) { . $serverScript }
if (Test-Path $intelScript) { . $intelScript }
if (Test-Path $topoScript) { . $topoScript }

$monitoredServers = @()
$serverCheckResults = @()
if (Get-Command Get-MonitoredServers -ErrorAction SilentlyContinue) {
    $monitoredServers = Get-MonitoredServers
    foreach ($srv in $monitoredServers) {
        if ($srv.PSObject.Properties['Enabled'] -and -not [bool]$srv.Enabled) { continue }
        $res = Check-SingleServer $srv
        $serverCheckResults += $res
        $st = switch ($res.Status) { 'Online' { 'PASS' } 'Degraded' { 'WARNING' } default { 'FAIL' } }
        $latTxt = if ($null -ne $res.LatencyMs) { "$($res.LatencyMs) ms" } else { "Failed" }
        Add-Check "Server: $($srv.Name)" "$($res.CheckType) check" "$($res.Status) ($latTxt)" $st $res.Detail
    }
}
if ($serverCheckResults.Count -eq 0) {
    Add-Check "Servers" "Configured servers" "0 configured" "INFO" "Configure remote servers in the Ambaan floating widget."
}


# Smart Auto Repair V3
# Only low-risk DNS cache flush is automatic, and only when DNS resolution failed.
# Network-disruptive/system-level repairs always require explicit confirmation.
$RepairLog = Join-Path $Reports "RepairLog.csv"
$RepairEvents = New-Object System.Collections.Generic.List[object]
$RepairApplied = $false
function Log-Repair {
    param([string]$Action,[string]$Reason,[string]$Result,[string]$Verification)
    $RepairEvents.Add([pscustomobject]@{
        Timestamp=(Get-Date).ToString("s"); Action=$Action; Reason=$Reason
        Result=$Result; Verification=$Verification
    }) | Out-Null
}
function Is-Admin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Host "`n=== SMART AUTO REPAIR ===" -ForegroundColor Cyan
if ($dnsStatus -eq "Failed") {
    Write-Host "DNS lookup failed. Applying safe repair: flush DNS resolver cache." -ForegroundColor Yellow
    ipconfig.exe /flushdns | Out-Null
    Start-Sleep -Seconds 2
    try {
        $null = Resolve-DnsName "www.microsoft.com" -Type A -DnsOnly -ErrorAction Stop
        $dnsStatus = "Working after DNS flush"
        $RepairApplied = $true
        Log-Repair "Flush DNS cache" "Initial DNS lookup failed" "Completed" "DNS lookup succeeded after repair"
        Add-Check "Auto repair" "Flush DNS cache" "Completed" "PASS" "DNS lookup succeeded on post-repair verification."
    } catch {
        Log-Repair "Flush DNS cache" "Initial DNS lookup failed" "Completed" "DNS still failing"
        Add-Check "Auto repair" "Flush DNS cache" "Applied; issue persists" "WARNING" "DNS still fails. This may be an upstream resolver or connectivity issue."
    }
} else {
    Log-Repair "No safe repair needed" "No DNS failure detected" "Skipped" "Not applicable"
    Add-Check "Auto repair" "Safe repair assessment" "No action needed" "INFO" "No safe automatic repair was indicated by this run."
}

# Risky repairs are offered only when local gateway measurements indicate a local-link problem.
$localIssue = ($router -and (($router.Loss -gt 5) -or ($null -ne $router.Avg -and $router.Avg -gt 20)))
if ($localIssue) {
    Write-Host "`nLocal router latency/loss is elevated. Possible network-disruptive repairs:" -ForegroundColor Yellow
    Write-Host "1. Renew DHCP lease (briefly interrupts connectivity)"
    Write-Host "2. Restart Wi-Fi adapter (disconnects Wi-Fi; Administrator required)"
    Write-Host "3. Skip risky repairs"
    $riskChoice = Read-Host "Choose 1-3 (default 3)"
    if ($riskChoice -eq "1") {
        $confirm = Read-Host "DHCP renew may interrupt active sessions. Type YES to proceed"
        if ($confirm -ceq "YES") {
            ipconfig.exe /release | Out-Null
            Start-Sleep -Seconds 2
            ipconfig.exe /renew | Out-Null
            Start-Sleep -Seconds 4
            $RepairApplied = $true
            Log-Repair "Renew DHCP lease" "Elevated router latency/loss" "Command completed" "Running post-repair tests"
        } else {
            Log-Repair "Renew DHCP lease" "Elevated router latency/loss" "Declined by user" "Not run"
        }
    } elseif ($riskChoice -eq "2") {
        if (-not (Is-Admin)) {
            Write-Warning "Restarting the adapter requires Administrator. No change made."
            Log-Repair "Restart Wi-Fi adapter" "Elevated router latency/loss" "Not run: Administrator required" "Not run"
        } else {
            $confirm = Read-Host "This will disconnect Wi-Fi temporarily. Type YES to proceed"
            if ($confirm -ceq "YES") {
                Restart-NetAdapter -Name $wifiName -Confirm:$false
                Start-Sleep -Seconds 8
                $RepairApplied = $true
                Log-Repair "Restart Wi-Fi adapter" "Elevated router latency/loss" "Command completed" "Running post-repair tests"
            } else {
                Log-Repair "Restart Wi-Fi adapter" "Elevated router latency/loss" "Declined by user" "Not run"
            }
        }
    } else {
        Log-Repair "Risky repair" "Local gateway issue" "Skipped by user" "Not run"
    }
} else {
    Log-Repair "Risky repair assessment" "No strong local gateway fault detected" "Not offered" "No disruptive action recommended"
}

# If safe DNS flush did not restore DNS, offer Winsock reset only with explicit approval.
if ($dnsStatus -ne "Working" -and $dnsStatus -ne "Working after DNS flush") {
    if (Is-Admin) {
        $winsockChoice = Read-Host "DNS still fails. Winsock reset is disruptive and usually requires reboot. Type RESET to approve, or press Enter to skip"
        if ($winsockChoice -ceq "RESET") {
            netsh.exe winsock reset | Out-Null
            $RepairApplied = $true
            Log-Repair "Winsock reset" "DNS still failed after cache flush" "Command completed; reboot required" "Reboot, then run analyzer again"
            Add-Check "Auto repair" "Winsock reset" "Completed; reboot required" "WARNING" "Run Windows restart, then verify connectivity."
        } else {
            Log-Repair "Winsock reset" "DNS still failed after cache flush" "Declined by user" "Not run"
        }
    } else {
        Log-Repair "Winsock reset" "DNS still failed after cache flush" "Not run: Administrator required" "Not run"
    }
}

# Post-repair verification: re-check router, internet reachability and DNS after any applied repair.
if ($RepairApplied) {
    Write-Host "`nVerifying network after repair..." -ForegroundColor Cyan
    Start-Sleep -Seconds 3
    if ($gateway) {
        $router = Ping-Target $gateway 10
        $routerVerify = if ($router.Loss -le 5 -and $null -ne $router.Avg) {"Router reachable; $($router.Loss)% loss; $($router.Avg) ms avg"} else {"Router still degraded; $($router.Loss)% loss"}
        Add-Check "Post-repair" "Router verification" $routerVerify $(if($router.Loss -le 5 -and $null -ne $router.Avg){"PASS"}else{"WARNING"})
    }
    $pingCloud = Ping-Target "1.1.1.1" 10
    Add-Check "Post-repair" "Internet verification" "$(if($null -ne $pingCloud.Avg){"$($pingCloud.Avg) ms avg; $($pingCloud.Loss)% loss"}else{"No replies"})" $(if($null -ne $pingCloud.Avg -and $pingCloud.Loss -le 5){"PASS"}else{"WARNING"})
    try {
        $null = Resolve-DnsName "www.microsoft.com" -Type A -DnsOnly -ErrorAction Stop
        $dnsStatus = "Working after verification"
        Add-Check "Post-repair" "DNS verification" "Working" "PASS"
    } catch {
        $dnsStatus = "Failed after verification"
        Add-Check "Post-repair" "DNS verification" "Still failing" "FAIL"
    }
    # Reflect the verified final state in the main status while retaining the repair audit trail.
    if ($dnsStatus -eq "Working after verification" -or $dnsStatus -eq "Working after DNS flush") {
        foreach ($item in $Results) {
            if ($item.Area -eq "DNS" -and $item.Check -eq "Resolution") {
                $item.Value = "Recovered after repair"
                $item.Status = "PASS"
                $item.Explanation = "Initial lookup failed; repair was applied and DNS subsequently verified."
            }
        }
    }
    if ($router -and $router.Loss -le 5 -and $null -ne $router.Avg) {
        foreach ($item in $Results) {
            if ($item.Area -eq "Local network" -and $item.Check -eq "Router latency") {
                $item.Value = "$($router.Avg) ms avg after repair"
                $item.Status = "PASS"
                $item.Explanation = "Post-repair router verification succeeded; see repair log for initial condition."
            }
        }
    }
} else {
    Add-Check "Post-repair" "Verification" "No repair applied" "INFO" "Initial diagnostic results remain the baseline."
}

# Persist repair log separately from performance history.
foreach ($event in $RepairEvents) {
    if (Test-Path $RepairLog) { $event | Export-Csv -Path $RepairLog -NoTypeInformation -Append -Encoding UTF8 }
    else { $event | Export-Csv -Path $RepairLog -NoTypeInformation -Encoding UTF8 }
}
$repairHtml = foreach ($event in $RepairEvents) {
    "<tr><td>$(HtmlEncode $event.Timestamp)</td><td>$(HtmlEncode $event.Action)</td><td>$(HtmlEncode $event.Result)</td><td>$(HtmlEncode $event.Verification)</td></tr>"
}
$repairHtml = ($repairHtml -join "`n")
$repairSummary = if ($RepairApplied) { "Repair action(s) applied; post-repair verification performed." } else { "No network-disruptive repair was applied." }

# Overall status and likely bottleneck heuristic
$failCount=@($Results | Where-Object Status -eq "FAIL").Count
$warnCount=@($Results | Where-Object Status -eq "WARNING").Count
$overall=if($failCount -gt 0){"ATTENTION REQUIRED"}elseif($warnCount -gt 0){"DEGRADED / REVIEW"}else{"NO ISSUES DETECTED"}
$likely="Insufficient evidence; compare wired and Wi-Fi tests."
if($router -and ($router.Loss -gt 0 -or ($router.Avg -ne $null -and $router.Avg -gt 10))){$likely="Likely local Wi-Fi/router segment: gateway latency or packet loss is elevated."}
elseif($router -and $router.Loss -eq 0 -and $pingCloud.Loss -gt 0 -and $pingGoogle.Loss -gt 0){$likely="Likely upstream of the router or ISP path; verify with Ethernet and another time window."}
elseif($router -and $router.Loss -eq 0 -and $router.Avg -lt 5 -and (($pingCloud.Avg -gt 80) -or ($pingGoogle.Avg -gt 80))){$likely="Local link looks responsive; likely WAN/ISP routing, congestion, or destination path."}
elseif($null -ne $down -and $down -lt 10 -and $signal -ge 80){$likely="Wi-Fi signal is strong but measured throughput is low; compare Ethernet and your plan to isolate router/ISP/server."}
elseif($signal -lt 50){$likely="Weak Wi-Fi signal is a likely contributor; test closer to the router."}

# Persist history, omitting identifiers
$record=[pscustomobject]@{
 Timestamp=$Now.ToString("s"); SignalPercent=$signal; RSSIdBm=$rssi; Band=$band; Channel=$channel
 LinkRxMbps=$rx;LinkTxMbps=$tx;RouterAvgMs=if($router){$router.Avg}else{$null}
 RouterLossPct=if($router){$router.Loss}else{$null};CloudflareAvgMs=$pingCloud.Avg;CloudflareLossPct=$pingCloud.Loss
 GoogleAvgMs=$pingGoogle.Avg;GoogleLossPct=$pingGoogle.Loss;DnsMs=$dnsMs;DownloadMbps=$down;UploadMbps=$up;Overall=$overall
}
if(Test-Path $Csv){$record|Export-Csv $Csv -NoTypeInformation -Append -Encoding UTF8}else{$record|Export-Csv $Csv -NoTypeInformation -Encoding UTF8}
$historyRows=@()
try{$historyRows=@(Import-Csv $Csv | Select-Object -Last 200)}catch{}
$historyJson=ConvertTo-Json -InputObject $historyRows -Depth 4 -Compress
$resultsJson=ConvertTo-Json -InputObject @($Results) -Depth 4 -Compress
$routeHtml=($routeLines | ForEach-Object {"<li>$(HtmlEncode $_)</li>"}) -join "`n"

# Recommendations
$recommendations=New-Object System.Collections.Generic.List[string]
if($signal -lt 70){$recommendations.Add("Move closer to the router and compare signal/RSSI; avoid placing the router behind metal or inside a cabinet.")}
if($router -and ($router.Loss -gt 0 -or ($router.Avg -gt 10))){$recommendations.Add("Local gateway response is elevated. Test near the router, pause heavy local transfers, and compare a wired Ethernet test.")}
if($pingCloud.Loss -gt 0 -or $pingGoogle.Loss -gt 0){$recommendations.Add("External ping loss observed. Repeat at another time and compare multiple destinations; ICMP may be deprioritized.")}
if($null -ne $down -and $down -lt 10){$recommendations.Add("Throughput is low in this sample. Compare against your subscribed plan, test via Ethernet, and repeat without VPN or large downloads.")}
if($dnsStatus -eq "Failed" -or ($dnsMs -gt 300)){$recommendations.Add("DNS resolution is failing or slow. Try another resolver only after confirming the issue is repeatable.")}
if($recommendations.Count -eq 0){$recommendations.Add("No strong fault was isolated in this run. Repeat during a slowdown and compare the historical graphs.")}
$recommendationHtml=($recommendations | ForEach-Object {"<li>$(HtmlEncode $_)</li>"}) -join "`n"
$checksHtml=foreach($r in $Results){
    $cls=switch($r.Status){"PASS"{"pass"}"WARNING"{"warn"}"FAIL"{"fail"}default{"info"}}
    "<tr><td>$(HtmlEncode $r.Area)</td><td>$(HtmlEncode $r.Check)</td><td>$(HtmlEncode $r.Value)</td><td><span class='pill $cls'>$(HtmlEncode $r.Status)</span></td><td>$(HtmlEncode $r.Explanation)</td></tr>"
}

# Monitored Servers Table HTML
$serverRowsHtml = foreach ($s in $serverCheckResults) {
    $cls = switch ($s.Status) { "Online" { "pass" } "Degraded" { "warn" } default { "fail" } }
    $lat = if ($null -ne $s.LatencyMs) { "$($s.LatencyMs) ms" } else { "-" }
    "<tr><td><span class='status-dot $cls'></span><strong>$(HtmlEncode $s.Name)</strong></td><td><code>$(HtmlEncode $s.Host)</code></td><td><span class='type-badge'>$(HtmlEncode $s.CheckType)</span></td><td><span class='pill $cls'>$(HtmlEncode $s.Status)</span></td><td class='mono'>$lat</td><td class='muted'>$(HtmlEncode $s.Detail)</td></tr>"
}
if (-not $serverRowsHtml -or $serverRowsHtml.Count -eq 0) {
    $serverRowsHtml = "<tr><td colspan='6' class='empty'>No remote servers configured. Add servers via the Ambaan floating widget (click Servers).</td></tr>"
} else {
    $serverRowsHtml = ($serverRowsHtml -join "`n")
}

# Network Anomalies Table HTML
$anomRowsHtml = @()
$anomCsv = Join-Path (Join-Path $Root "MonitorData") "Anomalies.csv"
if (Test-Path $anomCsv) {
    try {
        $recentAnoms = @(Import-Csv $anomCsv | Select-Object -Last 10 | Sort-Object Timestamp -Descending)
        $anomRowsHtml = foreach ($a in $recentAnoms) {
            $cls = switch ($a.Severity) { "Critical" { "fail" } "Warning" { "warn" } default { "info" } }
            "<tr><td class='mono'>$(HtmlEncode $a.Timestamp)</td><td><span class='type-badge'>$(HtmlEncode $a.Type)</span></td><td><span class='pill $cls'>$(HtmlEncode $a.Severity)</span></td><td><strong>$(HtmlEncode $a.Title)</strong></td><td class='muted'>$(HtmlEncode $a.Explanation)</td></tr>"
        }
    } catch {}
}
if (-not $anomRowsHtml -or $anomRowsHtml.Count -eq 0) {
    $anomRowsHtml = "<tr><td colspan='5' class='empty'>No network anomalies recorded. Connection behavior has been consistent.</td></tr>"
} else {
    $anomRowsHtml = ($anomRowsHtml -join "`n")
}

# Health Synthesis
$healthSynthesis = "Analysis in progress..."
if (Get-Command Get-NetworkHealthAssessment -ErrorAction SilentlyContinue) {
    $hObj = Get-NetworkHealthAssessment -wifi @{ Connected = $connected; Signal = $signal } `
                                        -routerMs $(if($router){$router.Avg}else{$null}) `
                                        -netMs $(if($pingCloud){$pingCloud.Avg}else{$null}) `
                                        -dnsStatus $(if($dnsSafe){$dnsSafe.Status}else{'Good'}) `
                                        -speedDown $down `
                                        -serverResults $serverCheckResults
    $healthSynthesis = (HtmlEncode $hObj.Summary)
}

# Topology Data
$topoJson = "{""Nodes"":[],""Links"":[]}"
if (Get-Command Get-NetworkTopologyGraph -ErrorAction SilentlyContinue) {
    $tGraph = Get-NetworkTopologyGraph -gatewayIp $gateway `
                                       -gatewayMac $(if($dnsSafe){"Gateway"}else{""}) `
                                       -routerMs $(if($router){$router.Avg}else{$null}) `
                                       -wifi @{ Connected = $connected; Signal = $signal; SSID = $ssid; Band = $band; Channel = $channel; RX = $rx; TX = $tx } `
                                       -lanDevices @() `
                                       -servers $serverCheckResults
    $topoJson = ConvertTo-Json -InputObject $tGraph -Depth 4 -Compress
}
$overallClass=if($overall -eq "NO ISSUES DETECTED"){"pass"}else{"warn"}
$dashboard=@'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ambaan Network Intelligence · Pro Dashboard</title>
<style>
:root{
  color-scheme:dark;
  --bg:#030712;
  --surface:#0b101d;
  --surface-raised:#111827;
  --surface-card:#0e1526;
  --border:rgba(255,255,255,0.08);
  --border-subtle:rgba(255,255,255,0.04);
  --border-focus:rgba(56,189,248,0.4);
  --ink:#f8fafc;
  --muted:#94a3b8;
  --subtle:#64748b;
  --sky:#38bdf8;
  --cyan:#22d3ee;
  --indigo:#818cf8;
  --emerald:#10b981;
  --amber:#f59e0b;
  --rose:#f43f5e;
  --shadow:0 12px 32px -4px rgba(0,0,0,0.6), 0 4px 12px -2px rgba(0,0,0,0.4);
  --inset-light:inset 0 1px 0 0 rgba(255,255,255,0.06);
}
*{box-sizing:border-box}
body{
  margin:0;
  background-color:var(--bg);
  background-image:
    radial-gradient(ellipse at 15% 0%,rgba(56,189,248,0.08) 0,transparent 45%),
    radial-gradient(ellipse at 85% 0%,rgba(129,140,248,0.07) 0,transparent 40%),
    radial-gradient(ellipse at 50% 100%,rgba(16,185,129,0.04) 0,transparent 50%);
  color:var(--ink);
  font:13.5px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;
  min-height:100vh;
  -webkit-font-smoothing:antialiased;
}
main{max-width:1440px;margin:auto;padding:32px 36px 64px}

/* Topbar */
.topbar{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:28px}
.brand{display:flex;align-items:center;gap:14px}
.brandmark{
  width:44px;height:44px;border-radius:12px;
  background:linear-gradient(135deg,#0284c7,#38bdf8 50%,#818cf8);
  display:grid;place-items:center;color:#030712;font-size:20px;font-weight:900;
  box-shadow:0 0 24px rgba(56,189,248,0.35);
}
.eyebrow{color:var(--sky);font-size:10px;letter-spacing:1.5px;text-transform:uppercase;font-weight:700}
.brand h1{font-size:21px;font-weight:700;letter-spacing:-0.4px;margin:2px 0 0}
.sub{color:var(--muted);font-size:12px}
.runmeta{text-align:right}
.runmeta .date{color:var(--subtle);font-size:11px;margin-top:6px;font-family:ui-monospace,SFMono-Regular,monospace}

/* Pills & Badges */
.pill,.tag{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;font-size:10px;letter-spacing:0.5px;font-weight:700;text-transform:uppercase;border:1px solid transparent}
.pass{background:rgba(16,185,129,0.12);color:#34d399;border-color:rgba(16,185,129,0.28)}
.warn{background:rgba(245,158,11,0.12);color:#fbbf24;border-color:rgba(245,158,11,0.28)}
.fail{background:rgba(244,63,94,0.12);color:#fb7185;border-color:rgba(244,63,94,0.28)}
.info{background:rgba(56,189,248,0.12);color:#38bdf8;border-color:rgba(56,189,248,0.28)}
.type-badge{display:inline-block;padding:2px 8px;border-radius:6px;background:rgba(255,255,255,0.05);border:1px solid var(--border);color:var(--muted);font-size:10px;font-weight:600}
.status-dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:8px}
.status-dot.pass{background:#10b981;box-shadow:0 0 8px #10b98188}
.status-dot.warn{background:#f59e0b;box-shadow:0 0 8px #f59e0b88}
.status-dot.fail{background:#f43f5e;box-shadow:0 0 8px #f43f5e88}

/* Hero Section */
.hero{
  position:relative;overflow:hidden;border:1px solid var(--border);
  border-radius:20px;padding:24px 28px;margin-bottom:20px;
  background:linear-gradient(135deg,#0c1626 0%,#09101d 55%,#110e24 100%);
  box-shadow:var(--shadow),var(--inset-light);
}
.hero:after{content:"";position:absolute;width:300px;height:300px;border-radius:50%;right:4%;top:-180px;background:radial-gradient(circle,rgba(56,189,248,0.12),transparent 70%);filter:blur(8px)}
.hero-inner{position:relative;z-index:1;display:flex;justify-content:space-between;align-items:center;gap:20px}
.hero h2{font-size:21px;font-weight:700;letter-spacing:-0.4px;margin:5px 0}
.hero p{margin:0;color:var(--muted);max-width:680px;font-size:13px}
.hero-stat{text-align:right;min-width:160px;padding-left:20px;border-left:1px solid var(--border)}
.hero-stat strong{display:block;font-size:26px;font-weight:800;letter-spacing:-0.5px;color:var(--ink)}
.hero-stat span{color:var(--subtle);font-size:11px}

/* Grid & Cards */
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:20px}
.metric-card,.panel{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:16px;
  box-shadow:var(--shadow),var(--inset-light);
}
.metric-card{padding:18px 20px;position:relative;overflow:hidden}
.metric-card:hover{border-color:rgba(255,255,255,0.14)}
.metric-card:after{content:"";position:absolute;width:80px;height:80px;right:-30px;bottom:-30px;border-radius:50%;background:var(--glow,#38bdf8);opacity:0.1;filter:blur(10px)}
.metric-head{display:flex;justify-content:space-between;align-items:center;color:var(--muted);font-size:11.5px;font-weight:600}
.metric-icon{width:28px;height:28px;display:grid;place-items:center;border-radius:8px;background:rgba(255,255,255,0.04);border:1px solid var(--border-subtle);color:var(--accent,var(--sky));font-size:14px;font-weight:700}
.metric{font-size:28px;font-weight:800;letter-spacing:-0.8px;margin:12px 0 2px;font-variant-numeric:tabular-nums}
.metric-foot{font-size:11px;color:var(--subtle)}

/* Panels & Layout */
.layout{display:grid;grid-template-columns:1.45fr 1fr;gap:16px;margin-bottom:16px}
.panel{padding:22px;margin-bottom:18px}
.panel-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:16px}
.panel h3{font-size:14px;font-weight:700;letter-spacing:-0.2px;margin:0}
.panel-kicker{color:var(--subtle);font-size:11px;margin-top:3px}
.tabs{display:flex;gap:4px;padding:3px;border:1px solid var(--border);background:#060a12;border-radius:10px}
.tabs button,button{font:inherit;color:var(--subtle);background:transparent;border:0;padding:5px 11px;border-radius:7px;cursor:pointer;font-size:11px;font-weight:600;transition:all 0.15s ease}
.tabs button:hover{color:var(--ink)}
.tabs button.active{background:var(--surface-raised);color:#fff;box-shadow:0 2px 8px rgba(0,0,0,0.4);border:1px solid var(--border)}
.chartwrap{height:245px;position:relative}
canvas{width:100%;height:245px;display:block}
.legend{display:flex;gap:18px;flex-wrap:wrap;margin-top:12px;color:var(--muted);font-size:11px}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px}

/* Diagnostics & Health Callouts */
.bottleneck{
  display:grid;grid-template-columns:1fr auto;align-items:center;gap:20px;
  background:linear-gradient(135deg,#0c1422,#090e18);
  border:1px solid var(--border);
  border-left:4px solid var(--sky);
  border-radius:16px;padding:20px 24px;margin-bottom:16px;
  box-shadow:var(--shadow),var(--inset-light);
}
.bottleneck h3{margin:0 0 6px;font-size:14px;font-weight:700}
.bottleneck p{margin:0;color:#cbd5e1;font-size:13px}
.signalbadge{font-size:11px;font-weight:600;color:var(--sky);border:1px solid rgba(56,189,248,0.3);background:rgba(56,189,248,0.08);padding:7px 12px;border-radius:10px;white-space:nowrap}

/* Stages */
.stages{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}
.stage{padding:14px 12px;border:1px solid var(--border);border-radius:12px;background:rgba(255,255,255,0.02);box-shadow:var(--inset-light)}
.stage:hover{border-color:rgba(255,255,255,0.12);background:rgba(255,255,255,0.03)}
.stage-num{font-size:10px;color:var(--sky);font-weight:800;letter-spacing:1px}
.stage strong{display:block;font-size:11.5px;margin:5px 0 2px}
.stage small{color:var(--subtle);font-size:10.5px}

/* Tables & Actions */
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.actions{list-style:none;padding:0;margin:0}
.actions li{padding:10px 0 10px 24px;position:relative;border-bottom:1px solid var(--border-subtle);color:#cbd5e1;font-size:12.5px}
.actions li:last-child{border-bottom:0}
.actions li:before{content:"→";position:absolute;left:0;color:var(--sky);font-weight:800}
.tablewrap{overflow:auto;border:1px solid var(--border);border-radius:12px;background:#070b13}
table{border-collapse:collapse;width:100%;font-size:11.5px;min-width:650px}
th,td{text-align:left;padding:12px 14px;border-bottom:1px solid var(--border-subtle);vertical-align:middle}
th{background:#090e18;color:var(--subtle);font-weight:700;text-transform:uppercase;letter-spacing:0.7px;font-size:9.5px;border-bottom:1px solid var(--border)}
tbody tr{transition:background 0.15s ease}
tbody tr:hover{background:rgba(255,255,255,0.03)}
tbody tr:last-child td{border-bottom:0}
code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px}
code{background:rgba(255,255,255,0.05);padding:2px 6px;border-radius:5px;border:1px solid var(--border-subtle);color:#e2e8f0}
.muted{color:var(--muted)}
.route{padding-left:20px;margin:8px 0;color:var(--muted);font-size:11.5px;line-height:1.8;font-family:ui-monospace,monospace}
.empty{color:var(--subtle);font-size:11.5px;padding:16px 14px;text-align:center}
.footer{color:var(--subtle);font-size:10.5px;line-height:1.7;margin:24px 4px 0;padding-top:16px;border-top:1px solid var(--border-subtle)}

/* Responsive */
@media(max-width:980px){main{padding:20px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.layout{grid-template-columns:1fr}.stages{grid-template-columns:repeat(2,minmax(0,1fr))}.two{grid-template-columns:1fr}}
@media(max-width:600px){main{padding:14px}.topbar,.hero-inner{align-items:flex-start;flex-direction:column}.runmeta,.hero-stat{text-align:left;padding-left:0;border-left:0}.grid{grid-template-columns:1fr 1fr;gap:8px}.metric-card{padding:14px}.metric{font-size:22px}.panel{padding:16px}.bottleneck{grid-template-columns:1fr}.signalbadge{width:max-content}.panel-head{flex-direction:column}.tabs{width:max-content}}
</style></head><body><main>
<header class="topbar">
 <div class="brand">
  <div class="brandmark">⌁</div>
  <div>
   <div class="eyebrow">Ambaan Network Intelligence Platform</div>
   <h1>Network Diagnostic <span style="color:var(--sky)">Center</span></h1>
   <div class="sub">Continuous local telemetry · automated anomaly detection · proactive health synthesis</div>
  </div>
 </div>
 <div class="runmeta">
  <span class="tag __OVERALLCLASS__">● __OVERALL__</span>
  <div class="date">Recorded __RUNDATE__</div>
 </div>
</header>

<section class="hero">
 <div class="hero-inner">
  <div>
   <div class="eyebrow">Diagnostic Overview</div>
   <h2>Live Telemetry &amp; Link Performance</h2>
   <p>Consolidated multi-layer network assessment across device adapters, local gateway, public transit hops, and DNS resolution paths. All measurements run locally with zero cloud telemetry.</p>
  </div>
  <div class="hero-stat">
   <strong>__SIGNAL__</strong>
   <span>Wi-Fi Signal · RSSI __RSSI__</span>
  </div>
 </div>
</section>

<section class="grid">
 <div class="metric-card" style="--accent:var(--sky);--glow:var(--sky)">
  <div class="metric-head"><span>Download Throughput</span><span class="metric-icon">↓</span></div>
  <div class="metric">__DOWN__</div>
  <div class="metric-foot">Host adapter sample (This PC)</div>
 </div>
 <div class="metric-card" style="--accent:var(--cyan);--glow:var(--cyan)">
  <div class="metric-head"><span>Upload Throughput</span><span class="metric-icon">↑</span></div>
  <div class="metric">__UP__</div>
  <div class="metric-foot">Host adapter sample (This PC)</div>
 </div>
 <div class="metric-card" style="--accent:var(--indigo);--glow:var(--indigo)">
  <div class="metric-head"><span>Internet Latency</span><span class="metric-icon">◷</span></div>
  <div class="metric">__PING__</div>
  <div class="metric-foot">Cloudflare ICMP roundtrip</div>
 </div>
 <div class="metric-card" style="--accent:var(--emerald);--glow:var(--emerald)">
  <div class="metric-head"><span>Radio Link Quality</span><span class="metric-icon">⌁</span></div>
  <div class="metric">__SIGNAL__</div>
  <div class="metric-foot">802.11 signal · RSSI __RSSI__</div>
 </div>
</section>

<div class="layout">
 <section class="panel">
  <div class="panel-head">
   <div><h3>Throughput History</h3><div class="panel-kicker">Bandwidth measurements over rolling time windows</div></div>
   <div class="tabs"><button class="active" data-range="1">24H</button><button data-range="7">7D</button><button data-range="30">30D</button></div>
  </div>
  <div class="chartwrap"><canvas id="speedChart"></canvas></div>
  <div class="legend"><span><i class="dot" style="background:#38bdf8"></i>Download · Mbps</span><span><i class="dot" style="background:#f59e0b"></i>Upload · Mbps</span></div>
 </section>

 <section class="panel">
  <div class="panel-head">
   <div><h3>Latency Response Trend</h3><div class="panel-kicker">Local router gateway vs external internet ICMP</div></div>
   <span class="tag info">LATENCY</span>
  </div>
  <div class="chartwrap"><canvas id="latencyChart"></canvas></div>
  <div class="legend"><span><i class="dot" style="background:#10b981"></i>Router · ms</span><span><i class="dot" style="background:#f43f5e"></i>Internet · ms</span></div>
 </section>
</div>

<section class="bottleneck">
 <div>
  <div class="eyebrow">Isolated Bottleneck</div>
  <h3>Where is connection performance limited?</h3>
  <p>__LIKELY__</p>
 </div>
 <div class="signalbadge">● Diagnostic Assessment</div>
</section>

<section class="bottleneck" style="margin-bottom:18px;border-left-color:var(--indigo);background:linear-gradient(135deg,#101128,#0c0e1e);">
 <div>
  <div class="eyebrow" style="color:var(--indigo);">Network Health Synthesis</div>
  <h3 style="color:#e0e7ff;">Multi-Signal Health Assessment</h3>
  <p style="white-space:pre-line;color:#cbd5e1;line-height:1.65;">__HEALTH_SUMMARY__</p>
 </div>
 <div class="signalbadge" style="border-color:rgba(129,140,248,0.4);color:var(--indigo);background:rgba(129,140,248,0.1);">● Intelligence Engine</div>
</section>

<section class="panel">
 <div class="panel-head">
  <div><h3>Interactive Network Topology</h3><div class="panel-kicker">Interactive network layout · <strong>Solid lines</strong> indicate directly measured radio/adapter links · <strong>Dashed lines</strong> indicate inferred Layer-2 subnet neighbors (ARP/NDP)</div></div>
  <span class="tag info">TOPOLOGY</span>
 </div>
 <div style="position:relative;height:340px;border-radius:14px;background:#050811;border:1px solid var(--border);overflow:hidden;">
  <canvas id="topoCanvas" style="width:100%;height:340px;"></canvas>
  <div id="topoCard" style="position:absolute;right:16px;top:16px;width:260px;background:rgba(11,16,29,0.92);backdrop-filter:blur(14px);border:1px solid rgba(255,255,255,0.14);border-radius:12px;padding:14px;font-size:11.5px;display:none;box-shadow:0 12px 36px rgba(0,0,0,0.7);">
   <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <strong id="topoTitle" style="color:var(--sky);font-size:12.5px;">Node Inspector</strong>
    <span id="topoBadge" class="pill pass" style="font-size:9px;">ONLINE</span>
   </div>
   <div id="topoBody" style="color:#cbd5e1;white-space:pre-wrap;font-family:ui-monospace,SFMono-Regular,monospace;font-size:10.5px;line-height:1.6;"></div>
  </div>
 </div>
</section>

<section class="panel">
 <div class="panel-head">
  <div><h3>Monitored Servers &amp; Services</h3><div class="panel-kicker">Real-time status of ping targets, TCP service ports, and HTTP/HTTPS endpoints</div></div>
  <span class="tag info">SERVICES</span>
 </div>
 <div class="tablewrap">
  <table>
   <thead><tr><th>Server Name</th><th>Host / Target</th><th>Check Type</th><th>Status</th><th>Latency</th><th>Detail</th></tr></thead>
   <tbody>__SERVERTABLE__</tbody>
  </table>
 </div>
</section>

<section class="panel">
 <div class="panel-head">
  <div><h3>Network Anomaly Intelligence</h3><div class="panel-kicker">IP conflicts, gateway changes, unexpected MAC shifts, and bandwidth spikes</div></div>
  <span class="tag warn">INTELLIGENCE</span>
 </div>
 <div class="tablewrap">
  <table>
   <thead><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>Anomaly Event</th><th>Diagnostic Explanation</th></tr></thead>
   <tbody>__ANOMALYTABLE__</tbody>
  </table>
 </div>
</section>

<section class="panel">
 <div class="panel-head"><div><h3>Five-Stage Network Path</h3><div class="panel-kicker">End-to-end traversal from device adapter to remote web services</div></div></div>
 <div class="stages">
  <div class="stage"><div class="stage-num">01 / ADAPTER</div><strong>PC → Wi-Fi Card</strong><small>Signal, driver, PHY rate</small></div>
  <div class="stage"><div class="stage-num">02 / GATEWAY</div><strong>Wi-Fi → Router</strong><small>Gateway latency, frame loss</small></div>
  <div class="stage"><div class="stage-num">03 / UPSTREAM</div><strong>Router → ISP</strong><small>WAN gateway, optical link</small></div>
  <div class="stage"><div class="stage-num">04 / TRANSIT</div><strong>ISP → Backbones</strong><small>Tier-1 transit, routing</small></div>
  <div class="stage"><div class="stage-num">05 / RESOLUTION</div><strong>DNS → Target</strong><small>Nameserver speed, lookup</small></div>
 </div>
</section>

<div class="two">
 <section class="panel"><div class="panel-head"><div><h3>Recommended Actions</h3><div class="panel-kicker">Prioritized based on this diagnostic run</div></div></div><ul class="actions">__RECOMMENDATIONS__</ul></section>
 <section class="panel"><div class="panel-head"><div><h3>Traceroute Hops</h3><div class="panel-kicker">Path to Cloudflare (1.1.1.1)</div></div></div><div class="sub" style="margin-bottom:8px;">Routers may deprioritize ICMP TTL replies; silent hops are standard behavior.</div><ul class="route">__ROUTE__</ul></section>
</div>

<section class="panel"><div class="panel-head"><div><h3>Smart Auto Repair</h3><div class="panel-kicker">Corrective actions taken and post-repair verification</div></div><span class="tag info">__REPAIRSUMMARY__</span></div><div class="tablewrap"><table><thead><tr><th>Time</th><th>Action Taken</th><th>Result</th><th>Verification</th></tr></thead><tbody>__REPAIRLOG__</tbody></table></div></section>
<section class="panel"><div class="panel-head"><div><h3>Full Diagnostic Measurement Log</h3><div class="panel-kicker">Comprehensive raw telemetry data</div></div></div><div class="tablewrap"><table><thead><tr><th>Subsystem</th><th>Check Performed</th><th>Observed Value</th><th>Status</th><th>Diagnostic Details</th></tr></thead><tbody>__CHECKS__</tbody></table></div></section>

<div class="footer">AMBAAN NETWORK INTELLIGENCE PLATFORM · Historical logs persisted locally in History\NetworkHistory.csv and MonitorData\. Identifiers and MAC addresses remain strictly private. Bandwidth testing transfers ~25 MB via Cloudflare edge endpoints. Speed reflects current radio medium and ISP transit load.</div>
</main>

<script>
const historyData = __HISTORY__;
const topoData = __TOPOLOGY_JSON__;

function draw(id, series, rows) {
  const c = document.getElementById(id);
  if (!c) return;
  const ctx = c.getContext('2d'), dpr = window.devicePixelRatio || 1;
  const w = Math.max(c.clientWidth, 260), h = 245;
  c.width = w * dpr; c.height = h * dpr;
  ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
  
  const pad = { l: 45, r: 16, t: 16, b: 28 }, cw = w - pad.l - pad.r, ch = h - pad.t - pad.b;
  ctx.font = '10px -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif';
  ctx.fillStyle = '#64748b';
  ctx.strokeStyle = 'rgba(255,255,255,0.06)';
  ctx.lineWidth = 1;
  
  let vals = [];
  series.forEach(s => rows.forEach(r => { let v = Number(r[s.key]); if (Number.isFinite(v)) vals.push(v); }));
  let max = Math.max(10, ...vals) * 1.15, min = 0;
  
  // Grid lines
  for (let i = 0; i <= 4; i++) {
    let y = pad.t + ch * i / 4;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(w - pad.r, y); ctx.stroke();
    ctx.fillText((max - (max - min) * i / 4).toFixed(0), 8, y + 3);
  }
  
  if (rows.length === 0) {
    ctx.fillStyle = '#94a3b8'; ctx.textAlign = 'center';
    ctx.fillText('No telemetry records in this window yet', w / 2, h / 2);
    ctx.textAlign = 'left';
    return;
  }
  
  series.forEach(s => {
    let coords = [];
    rows.forEach((r, i) => {
      let v = Number(r[s.key]);
      if (!Number.isFinite(v)) return;
      let x = pad.l + (rows.length < 2 ? cw / 2 : i * cw / (rows.length - 1));
      let y = pad.t + ch - (v - min) / (max - min) * ch;
      coords.push([x, y]);
    });
    if (coords.length === 0) return;
    
    // Area fill
    let grad = ctx.createLinearGradient(0, pad.t, 0, pad.t + ch);
    grad.addColorStop(0, s.color + '33');
    grad.addColorStop(1, s.color + '00');
    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.moveTo(coords[0][0], pad.t + ch);
    coords.forEach(([x, y]) => ctx.lineTo(x, y));
    ctx.lineTo(coords[coords.length - 1][0], pad.t + ch);
    ctx.closePath();
    ctx.fill();
    
    // Stroke line
    ctx.strokeStyle = s.color;
    ctx.lineWidth = 2.2;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    ctx.beginPath();
    coords.forEach(([x, y], idx) => { if (idx === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y); });
    ctx.stroke();
    
    // Data points
    ctx.fillStyle = s.color;
    coords.forEach(([x, y]) => {
      ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2); ctx.fill();
    });
  });
  
  ctx.fillStyle = '#64748b';
  ctx.fillText(rows.length + ' data points', pad.l, h - 8);
}

let activeNode = null;
const nodePositions = {};

function renderTopo() {
  const c = document.getElementById('topoCanvas');
  if (!c || !topoData || !topoData.Nodes) return;
  const ctx = c.getContext('2d'), dpr = window.devicePixelRatio || 1;
  const w = c.clientWidth, h = 340;
  c.width = w * dpr; c.height = h * dpr;
  ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
  
  // Background grid dots
  ctx.fillStyle = 'rgba(255,255,255,0.03)';
  for (let gx = 20; gx < w; gx += 28) {
    for (let gy = 20; gy < h; gy += 28) {
      ctx.fillRect(gx, gy, 1.5, 1.5);
    }
  }
  
  // Calculate node layout positions
  nodePositions['node-internet'] = { x: 80, y: h / 2, label: 'Internet', status: 'Online', sub: 'Cloudflare / WAN', icon: '🌐' };
  nodePositions['node-router'] = { x: 250, y: h / 2, label: 'Main Router', status: 'Online', sub: 'Gateway', icon: '⚡' };
  
  const leaves = topoData.Nodes.filter(n => n.Id !== 'node-internet' && n.Id !== 'node-router');
  const count = Math.max(1, leaves.length);
  const step = Math.min(56, (h - 60) / count);
  let curY = Math.max(40, (h - (count - 1) * step) / 2);
  
  leaves.forEach((n) => {
    let icon = n.Id.includes('pc') ? '💻' : (n.Id.includes('srv') ? '🖥️' : '📱');
    nodePositions[n.Id] = {
      x: Math.min(w - 180, 520),
      y: curY,
      label: n.Label,
      status: n.Status,
      sub: n.SubText,
      details: n.Details,
      icon: icon
    };
    curY += step;
  });
  
  // Draw smooth Bezier connections (Observed solid vs Inferred dashed)
  (topoData.Links || []).forEach(l => {
    const p1 = nodePositions[l.From], p2 = nodePositions[l.To];
    if (p1 && p2) {
      const midX = (p1.x + p2.x) / 2;
      ctx.beginPath();
      if (l.Dashed) {
        ctx.setLineDash([5, 5]);
      } else {
        ctx.setLineDash([]);
      }
      ctx.moveTo(p1.x, p1.y);
      ctx.bezierCurveTo(midX, p1.y, midX, p2.y, p2.x, p2.y);
      let isHigh = (activeNode && (activeNode.id === l.From || activeNode.id === l.To));
      ctx.strokeStyle = isHigh ? '#38bdf8' : (l.Dashed ? 'rgba(148,163,184,0.3)' : 'rgba(56,189,248,0.35)');
      ctx.lineWidth = isHigh ? 2.5 : (l.Dashed ? 1.2 : 1.8);
      ctx.stroke();
      ctx.setLineDash([]);
    }
  });
  
  // Draw Nodes
  topoData.Nodes.forEach(n => {
    const p = nodePositions[n.Id];
    if (!p) return;
    const isAct = (activeNode && activeNode.id === n.Id);
    
    // Halo glow
    let haloCol = n.Status === 'Online' ? 'rgba(16,185,129,0.18)' : (n.Status === 'Degraded' ? 'rgba(245,158,11,0.18)' : 'rgba(244,63,94,0.18)');
    let strokeCol = n.Status === 'Online' ? '#10b981' : (n.Status === 'Degraded' ? '#f59e0b' : '#f43f5e');
    
    ctx.beginPath();
    ctx.arc(p.x, p.y, isAct ? 22 : 18, 0, Math.PI * 2);
    ctx.fillStyle = haloCol;
    ctx.fill();
    
    // Inner node circle
    ctx.beginPath();
    ctx.arc(p.x, p.y, 14, 0, Math.PI * 2);
    ctx.fillStyle = isAct ? '#1e293b' : '#0f172a';
    ctx.fill();
    ctx.strokeStyle = isAct ? '#38bdf8' : strokeCol;
    ctx.lineWidth = isAct ? 2.2 : 1.8;
    ctx.stroke();
    
    // Node icon
    ctx.font = '12px Segoe UI Emoji, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(p.icon || '●', p.x, p.y);
    
    // Label
    ctx.textAlign = 'left';
    ctx.font = '600 11.5px -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif';
    ctx.fillStyle = isAct ? '#38bdf8' : '#f8fafc';
    ctx.fillText(p.label, p.x + 24, p.y - 2);
    
    // Subtext
    if (p.sub) {
      ctx.font = '10px ui-monospace,SFMono-Regular,monospace';
      ctx.fillStyle = '#64748b';
      ctx.fillText(p.sub, p.x + 24, p.y + 12);
    }
  });
}

function render(days) {
  const cutoff = Date.now() - days * 86400000;
  const rows = historyData.filter(r => { const t = Date.parse(r.Timestamp); return Number.isFinite(t) && t >= cutoff; });
  draw('speedChart', [{ key: 'DownloadMbps', color: '#38bdf8' }, { key: 'UploadMbps', color: '#f59e0b' }], rows);
  draw('latencyChart', [{ key: 'RouterAvgMs', color: '#10b981' }, { key: 'CloudflareAvgMs', color: '#f43f5e' }], rows);
}

document.querySelectorAll('[data-range]').forEach(b => b.addEventListener('click', () => {
  document.querySelectorAll('[data-range]').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  render(Number(b.dataset.range));
}));

render(1);
renderTopo();
window.addEventListener('resize', () => {
  const activeBtn = document.querySelector('.tabs .active');
  render(activeBtn ? Number(activeBtn.dataset.range) : 1);
  renderTopo();
});

const topoCanvas = document.getElementById('topoCanvas');
if (topoCanvas) {
  function handleTopoHit(e) {
    const rect = topoCanvas.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    if (!topoData || !topoData.Nodes) return null;
    for (let n of topoData.Nodes) {
      const p = nodePositions[n.Id];
      if (p && Math.hypot(mx - p.x, my - p.y) < 26) {
        return { node: n, pos: p };
      }
    }
    return null;
  }
  
  topoCanvas.addEventListener('mousemove', (e) => {
    const hit = handleTopoHit(e);
    topoCanvas.style.cursor = hit ? 'pointer' : 'default';
  });
  
  topoCanvas.addEventListener('click', (e) => {
    const hit = handleTopoHit(e);
    if (hit) {
      activeNode = { id: hit.node.Id };
      const card = document.getElementById('topoCard');
      const title = document.getElementById('topoTitle');
      const badge = document.getElementById('topoBadge');
      const body = document.getElementById('topoBody');
      
      card.style.display = 'block';
      title.textContent = hit.pos.label;
      badge.textContent = hit.pos.status.toUpperCase();
      badge.className = 'pill ' + (hit.pos.status === 'Online' ? 'pass' : (hit.pos.status === 'Degraded' ? 'warn' : 'fail'));
      let info = '';
      if (hit.node.Relationship) info += '[RELATIONSHIP]: ' + hit.node.Relationship + '\n';
      if (hit.node.Confidence) info += '[CONFIDENCE]: ' + hit.node.Confidence + '\n\n';
      info += (hit.node.Details || hit.pos.sub || 'No extra telemetry parameters.');
      body.textContent = info;
      renderTopo();
    } else {
      activeNode = null;
      document.getElementById('topoCard').style.display = 'none';
      renderTopo();
    }
  });
}
</script></body></html>
'@
# Replace template tokens one at a time. Keeping this explicit avoids PowerShell
# line-continuation / method-chain parsing issues that can leave raw tokens in HTML.
$downDisplay = if ($null -ne $down) { "$down Mbps" } else { "N/A" }
$upDisplay = if ($null -ne $up) { "$up Mbps" } else { "N/A" }
$pingDisplay = if ($null -ne $pingCloud.Avg) { "$($pingCloud.Avg) ms" } else { "N/A" }
$signalDisplay = if ($null -ne $signal) { "$signal%" } else { "N/A" }
$rssiDisplay = if ($null -ne $rssi) { "$rssi dBm" } else { "N/A" }
$replacements = [ordered]@{
    "__OVERALLCLASS__" = $overallClass
    "__OVERALL__" = (HtmlEncode $overall)
    "__RUNDATE__" = (HtmlEncode $Now.ToString("yyyy-MM-dd HH:mm:ss"))
    "__DOWN__" = $downDisplay
    "__UP__" = $upDisplay
    "__PING__" = $pingDisplay
    "__SIGNAL__" = $signalDisplay
    "__RSSI__" = $rssiDisplay
    "__LIKELY__" = (HtmlEncode $likely)
    "__RECOMMENDATIONS__" = $recommendationHtml
    "__ROUTE__" = $routeHtml
    "__CHECKS__" = ($checksHtml -join "`n")
    "__HISTORY__" = $historyJson
    "__RESULTS__" = $resultsJson
    "__REPAIRSUMMARY__" = (HtmlEncode $repairSummary)
    "__REPAIRLOG__" = $repairHtml
    "__SERVERTABLE__" = $serverRowsHtml
    "__ANOMALYTABLE__" = $anomRowsHtml
    "__HEALTH_SUMMARY__" = $healthSynthesis
    "__TOPOLOGY_JSON__" = $topoJson
}
foreach ($token in $replacements.Keys) {
    $dashboard = $dashboard.Replace([string]$token, [string]$replacements[$token])
}
$dashboard | Set-Content -Path $HtmlReport -Encoding UTF8

# Plain-text report
$txt=New-Object System.Collections.Generic.List[string]
$txt.Add("WI-FI NETWORK ANALYZER PRO");$txt.Add("Run: $($Now.ToString('yyyy-MM-dd HH:mm:ss'))");$txt.Add("Overall: $overall")
$txt.Add("Likely bottleneck: $likely");$txt.Add("");$txt.Add("Privacy: identifiers and IP addresses omitted.")
foreach($r in $Results){$txt.Add("$($r.Area) | $($r.Check) | $($r.Value) | $($r.Status)");if($r.Explanation){$txt.Add("  $($r.Explanation)")}}
$txt.Add("");$txt.Add("SMART AUTO REPAIR: $repairSummary");foreach($event in $RepairEvents){$txt.Add("$($event.Action) | $($event.Result) | $($event.Verification)")};$txt.Add("");$txt.Add("Recommendations:");foreach($x in $recommendations){$txt.Add("- $x")}
$txt | Set-Content $TxtReport -Encoding UTF8

Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Overall: $overall"
Write-Host "Likely bottleneck: $likely"
Write-Host "`nDashboard: $HtmlReport" -ForegroundColor Green
Write-Host "Text report: $TxtReport"
Write-Host "History: $Csv"
Write-Host "`nOpening dashboard..." -ForegroundColor Cyan
Start-Process $HtmlReport

Write-Host "`nRepair log: $RepairLog" -ForegroundColor Cyan
Write-Host "Dashboard and reports updated with repair actions and verification." -ForegroundColor Green
Write-Host "`nDone. Press Enter to close."
Read-Host | Out-Null
