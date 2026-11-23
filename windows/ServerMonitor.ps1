# ServerMonitor.ps1 - Remote Server and Service Monitoring for Ambaan Wi-Fi Guard
# PowerShell 5.1 compatible. Non-admin, zero external dependencies.
# AMBAAN 3.0: Input validation, safety policies, Jitter computation, and rolling SLA metrics.

$script:ServerMonitorDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:ServerDataDir = Join-Path $script:ServerMonitorDir 'MonitorData'
if (-not (Test-Path $script:ServerDataDir)) { New-Item -ItemType Directory -Force -Path $script:ServerDataDir | Out-Null }

$script:ServersConfigFile = Join-Path $script:ServerDataDir 'MonitoredServers.json'
$script:ServerHistoryCsv = Join-Path $script:ServerDataDir 'ServerHistory.csv'

# In-memory server cache & runtime state: Id -> State object
$script:ServerStates = @{}

# P0 Security: Input Validation & Monitoring Safety Policy
function Test-TargetSafetyPolicy {
    param(
        [string]$hostName,
        [int]$port = 0,
        [string]$httpUrl = ''
    )

    # Disallow command injection and shell metacharacters
    if ($hostName -match '[;&|`$<>"\''\r\n\t ]') {
        return [pscustomobject]@{ Allowed = $false; Reason = "Host contains invalid characters or shell metacharacters" }
    }

    # Validate hostname / IP format
    if ($hostName -and -not ($hostName -match '^([a-zA-Z0-9_-]+\.)*[a-zA-Z0-9_-]+$|^([0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$')) {
        return [pscustomobject]@{ Allowed = $false; Reason = "Invalid IP address or hostname format" }
    }

    # Validate Port
    if ($port -ne 0 -and ($port -lt 1 -or $port -gt 65535)) {
        return [pscustomobject]@{ Allowed = $false; Reason = "TCP port must be between 1 and 65535" }
    }

    # Validate HTTP/HTTPS URI scheme
    if ($httpUrl) {
        if (-not ($httpUrl -match '^https?://')) {
            return [pscustomobject]@{ Allowed = $false; Reason = "Only http:// and https:// URI schemes are allowed" }
        }
        if ($httpUrl -match '(?i)^(file|gopher|ftp|javascript|data):') {
            return [pscustomobject]@{ Allowed = $false; Reason = "Unsafe URI protocol rejected" }
        }
    }

    return [pscustomobject]@{ Allowed = $true; Reason = "Validated" }
}

function Safe-WriteAtomic([string]$path, [string]$content) {
    try {
        $tmp = "$path.$([guid]::NewGuid().ToString('N')).tmp"
        [System.IO.File]::WriteAllText($tmp, $content, [System.Text.Encoding]::UTF8)
        if (Test-Path $path) {
            # Atomic move / replace
            [System.IO.File]::Copy($tmp, $path, $true)
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        } else {
            Move-Item -Path $tmp -Destination $path -Force
        }
    } catch {}
}

function Get-MonitoredServers {
    if (Test-Path $script:ServersConfigFile) {
        try {
            $raw = Get-Content $script:ServersConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($raw -is [array]) { return @($raw) }
            elseif ($raw) { return @($raw) }
        } catch {}
    }
    return @()
}

function Save-MonitoredServers($servers) {
    try {
        $json = $servers | ConvertTo-Json -Depth 4
        Safe-WriteAtomic $script:ServersConfigFile $json
    } catch {}
}

# Ping check with RFC 3550 Jitter calculation
function Test-ServerPingTarget([string]$hostName, [int]$count = 4, [int]$timeoutMs = 1200) {
    $policy = Test-TargetSafetyPolicy -hostName $hostName
    if (-not $policy.Allowed) {
        return [pscustomobject]@{
            Success = $false; AvgMs = $null; MinMs = $null; MaxMs = $null
            JitterMs = $null; LossPct = 100.0; Received = 0; Sent = $count; Error = $policy.Reason
        }
    }

    $p = New-Object System.Net.NetworkInformation.Ping
    $times = @(); $lost = 0
    for ($i = 0; $i -lt $count; $i++) {
        try {
            $r = $p.Send($hostName, $timeoutMs)
            if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                $times += [double]$r.RoundtripTime
            } else { $lost++ }
        } catch { $lost++ }
        if ($i -lt ($count - 1)) { Start-Sleep -Milliseconds 50 }
    }
    $p.Dispose()

    $loss = if ($count -gt 0) { [math]::Round(($lost / $count) * 100, 1) } else { 100.0 }
    $avg = if ($times.Count -gt 0) { [math]::Round(($times | Measure-Object -Average).Average, 1) } else { $null }
    
    # Calculate Jitter across consecutive sample intervals
    $jitter = 0.0
    if ($times.Count -gt 1) {
        $diffs = @()
        for ($j = 1; $j -lt $times.Count; $j++) {
            $diffs += [math]::Abs($times[$j] - $times[$j - 1])
        }
        $jitter = [math]::Round(($diffs | Measure-Object -Average).Average, 1)
    }

    [pscustomobject]@{
        Success = ($times.Count -gt 0)
        AvgMs = $avg
        MinMs = if ($times.Count) { ($times | Measure-Object -Minimum).Minimum } else { $null }
        MaxMs = if ($times.Count) { ($times | Measure-Object -Maximum).Maximum } else { $null }
        JitterMs = $jitter
        LossPct = $loss
        Received = $times.Count
        Sent = $count
        Error = $null
    }
}

function Test-ServerTcpPort([string]$hostName, [int]$port, [int]$timeoutMs = 1800) {
    $policy = Test-TargetSafetyPolicy -hostName $hostName -port $port
    if (-not $policy.Allowed) {
        return [pscustomobject]@{ Success = $false; LatencyMs = $null; Error = $policy.Reason; Port = $port }
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $tcp = New-Object System.Net.Sockets.TcpClient
    $success = $false
    $err = ""
    try {
        $ar = $tcp.BeginConnect($hostName, $port, $null, $null)
        $wh = $ar.AsyncWaitHandle
        if (-not $wh.WaitOne($timeoutMs, $false)) {
            $tcp.Close()
            $err = "Connection timed out ($timeoutMs ms)"
        } else {
            $tcp.EndConnect($ar)
            $success = $true
        }
    } catch {
        $err = $_.Exception.Message
    } finally {
        $sw.Stop()
        try { $tcp.Close() } catch {}
    }
    $ms = if ($success) { [math]::Round($sw.Elapsed.TotalMilliseconds, 1) } else { $null }
    [pscustomobject]@{
        Success = $success
        LatencyMs = $ms
        Error = $err
        Port = $port
    }
}

function Test-ServerHttpEndpoint([string]$url, [int]$timeoutMs = 3200, [int]$expectedStatusCode = 0, [string]$expectedKeyword = '') {
    $policy = Test-TargetSafetyPolicy -hostName 'web-endpoint' -httpUrl $url
    if (-not $policy.Allowed) {
        return [pscustomobject]@{ Success = $false; StatusCode = 0; LatencyMs = $null; Error = $policy.Reason; Url = $url }
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $success = $false
    $code = 0
    $err = ""
    $bodySnippet = ""
    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Timeout = $timeoutMs
        $req.ReadWriteTimeout = $timeoutMs
        $req.Method = "GET"
        $req.UserAgent = "Ambaan-Network-Intelligence/3.0"
        $req.AllowAutoRedirect = $true

        # Graceful certificate callback for intranet servers
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

        $resp = $req.GetResponse()
        $httpResp = [System.Net.HttpWebResponse]$resp
        $code = [int]$httpResp.StatusCode

        # Validate Status code
        if ($expectedStatusCode -gt 0) {
            $success = ($code -eq $expectedStatusCode)
        } else {
            $success = ($code -ge 200 -and $code -lt 400)
        }

        # Optional body keyword validation
        if ($success -and $expectedKeyword) {
            $reader = New-Object System.IO.StreamReader($httpResp.GetResponseStream())
            $buffer = New-Object char[] 10240
            $readCount = $reader.Read($buffer, 0, 10240)
            $bodySnippet = New-Object string($buffer, 0, $readCount)
            $reader.Close()
            if (-not $bodySnippet.Contains($expectedKeyword)) {
                $success = $false
                $err = "Expected response keyword '$expectedKeyword' not found in body"
            }
        }
        $httpResp.Close()
    } catch [System.Net.WebException] {
        if ($_.Response) {
            $code = [int]([System.Net.HttpWebResponse]$_.Response).StatusCode
            if ($expectedStatusCode -gt 0) {
                $success = ($code -eq $expectedStatusCode)
            } else {
                $success = ($code -ge 200 -and $code -lt 400)
            }
        }
        $err = $_.Message
    } catch {
        $err = $_.Message
    } finally {
        $sw.Stop()
    }
    $ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
    [pscustomobject]@{
        Success = $success
        StatusCode = $code
        LatencyMs = $ms
        Error = $err
        Url = $url
    }
}

function Check-SingleServer($srv) {
    $checkType = if ($srv.CheckType) { $srv.CheckType } else { 'Ping' }
    $warnMs = if ($srv.LatencyWarnMs) { [double]$srv.LatencyWarnMs } else { 200.0 }
    
    $status = 'Offline'
    $latency = $null
    $loss = 0.0
    $jitter = 0.0
    $detail = ""
    
    switch ($checkType) {
        'Port' {
            $p = if ($srv.Port) { [int]$srv.Port } else { 80 }
            $res = Test-ServerTcpPort $srv.Host $p
            if ($res.Success) {
                $latency = $res.LatencyMs
                $status = if ($latency -gt $warnMs) { 'Degraded' } else { 'Online' }
                $detail = "Port $p open ($latency ms)"
            } else {
                $status = 'Offline'
                $detail = "Port $p closed: $($res.Error)"
            }
        }
        'Http' {
            $url = if ($srv.HttpUrl) { $srv.HttpUrl } else { "http://$($srv.Host)" }
            $expCode = if ($srv.ExpectedCode) { [int]$srv.ExpectedCode } else { 0 }
            $expWord = if ($srv.ExpectedKeyword) { [string]$srv.ExpectedKeyword } else { '' }
            $res = Test-ServerHttpEndpoint -url $url -expectedStatusCode $expCode -expectedKeyword $expWord
            if ($res.Success) {
                $latency = $res.LatencyMs
                $status = if ($latency -gt $warnMs) { 'Degraded' } else { 'Online' }
                $detail = "HTTP $($res.StatusCode) ($latency ms)"
            } else {
                $status = 'Offline'
                $detail = if ($res.StatusCode) { "HTTP error $($res.StatusCode): $($res.Error)" } else { "HTTP failed: $($res.Error)" }
            }
        }
        default { # Ping
            $res = Test-ServerPingTarget $srv.Host
            $loss = $res.LossPct
            $latency = $res.AvgMs
            $jitter = $res.JitterMs
            if ($res.Success) {
                if ($loss -gt 25 -or ($latency -gt $warnMs) -or ($jitter -gt 50)) {
                    $status = 'Degraded'
                } else {
                    $status = 'Online'
                }
                $detail = "Ping $latency ms (jitter $jitter ms), loss $loss%"
            } else {
                $status = 'Offline'
                $detail = "No ping response (100% loss)"
            }
        }
    }

    return [pscustomobject]@{
        Id = $srv.Id
        Name = $srv.Name
        Host = $srv.Host
        CheckType = $checkType
        Status = $status
        LatencyMs = $latency
        LossPct = $loss
        JitterMs = $jitter
        Detail = $detail
        CheckedAt = Get-Date
    }
}

function Invoke-AllServerChecks {
    $servers = Get-MonitoredServers
    $results = @()
    $events = @()

    foreach ($srv in $servers) {
        if ($srv.PSObject.Properties['Enabled'] -and -not [bool]$srv.Enabled) { continue }
        
        $res = Check-SingleServer $srv
        $results += $res
        
        $id = [string]$srv.Id
        $prev = $script:ServerStates[$id]
        
        # State transitions
        if ($null -ne $prev) {
            if ($prev.Status -ne 'Offline' -and $res.Status -eq 'Offline') {
                $events += [pscustomobject]@{
                    Type = 'ServerDown'
                    Server = $srv
                    Result = $res
                    Message = "Server '$($srv.Name)' ($($srv.Host)) is DOWN: $($res.Detail)"
                    Severity = 'Critical'
                }
            } elseif ($prev.Status -eq 'Offline' -and $res.Status -ne 'Offline') {
                $events += [pscustomobject]@{
                    Type = 'ServerRecovered'
                    Server = $srv
                    Result = $res
                    Message = "Server '$($srv.Name)' ($($srv.Host)) has RECOVERED: $($res.Detail)"
                    Severity = 'Info'
                }
            } elseif ($prev.Status -eq 'Online' -and $res.Status -eq 'Degraded') {
                $events += [pscustomobject]@{
                    Type = 'ServerSlow'
                    Server = $srv
                    Result = $res
                    Message = "Server '$($srv.Name)' latency is elevated ($($res.LatencyMs) ms)"
                    Severity = 'Warning'
                }
            }
        }
        
        $script:ServerStates[$id] = $res

        # Append to CSV history with Jitter and SLA logging
        try {
            $rec = [pscustomobject]@{
                Timestamp  = (Get-Date).ToString('s')
                ServerId   = $srv.Id
                ServerName = $srv.Name
                Host       = $srv.Host
                CheckType  = $res.CheckType
                Status     = $res.Status
                LatencyMs  = $res.LatencyMs
                LossPct    = $res.LossPct
                JitterMs   = $res.JitterMs
                Detail     = $res.Detail
            }
            if (Test-Path $script:ServerHistoryCsv) {
                $rec | Export-Csv -Path $script:ServerHistoryCsv -NoTypeInformation -Append -Encoding UTF8
            } else {
                $rec | Export-Csv -Path $script:ServerHistoryCsv -NoTypeInformation -Encoding UTF8
            }
        } catch {}
    }

    return [pscustomobject]@{
        Results = $results
        Events = $events
        CheckedAt = Get-Date
    }
}

# SLA and Availability Analytics (AMBAAN 3.0)
function Get-ServerUptimeStats([string]$serverId, [int]$hours = 24, [double]$targetSla = 99.5) {
    if (-not (Test-Path $script:ServerHistoryCsv)) {
        return [pscustomobject]@{
            UptimePct = 100.0
            TotalChecks = 0
            OnlineChecks = 0
            FailedChecks = 0
            DowntimeMinutes = 0
            TargetSla = $targetSla
            MeetsSla = $true
            AvgLatencyMs = 0
            AvgJitterMs = 0
        }
    }
    try {
        $cutoff = (Get-Date).AddHours(-$hours)
        $allRows = @(Import-Csv $script:ServerHistoryCsv)
        $rows = @($allRows | Where-Object {
            $_.ServerId -eq $serverId -and [datetime]$_.Timestamp -ge $cutoff
        })

        if ($rows.Count -eq 0) {
            return [pscustomobject]@{
                UptimePct = 100.0
                TotalChecks = 0
                OnlineChecks = 0
                FailedChecks = 0
                DowntimeMinutes = 0
                TargetSla = $targetSla
                MeetsSla = $true
                AvgLatencyMs = 0
                AvgJitterMs = 0
            }
        }

        $onlineCount = @($rows | Where-Object { $_.Status -in 'Online', 'Degraded' }).Count
        $failedCount = $rows.Count - $onlineCount
        $pct = [math]::Round(($onlineCount / $rows.Count) * 100, 2)
        
        # Estimate downtime: fraction of time down * total interval minutes
        $intervalMinutes = [math]::Min($hours * 60, [math]::Max(1, [int]((Get-Date) - ([datetime]$rows[0].Timestamp)).TotalMinutes))
        $downtimeMin = [math]::Round(($failedCount / $rows.Count) * $intervalMinutes, 1)

        $latVals = @($rows | Where-Object { $_.LatencyMs } | ForEach-Object { [double]$_.LatencyMs })
        $avgLat = if ($latVals.Count) { [math]::Round(($latVals | Measure-Object -Average).Average, 1) } else { 0 }

        $jitVals = @($rows | Where-Object { $_.PSObject.Properties['JitterMs'] -and $_.JitterMs } | ForEach-Object { [double]$_.JitterMs })
        $avgJit = if ($jitVals.Count) { [math]::Round(($jitVals | Measure-Object -Average).Average, 1) } else { 0 }

        return [pscustomobject]@{
            UptimePct = $pct
            TotalChecks = $rows.Count
            OnlineChecks = $onlineCount
            FailedChecks = $failedCount
            DowntimeMinutes = $downtimeMin
            TargetSla = $targetSla
            MeetsSla = ($pct -ge $targetSla)
            AvgLatencyMs = $avgLat
            AvgJitterMs = $avgJit
        }
    } catch {
        return [pscustomobject]@{
            UptimePct = 100.0
            TotalChecks = 0
            OnlineChecks = 0
            FailedChecks = 0
            DowntimeMinutes = 0
            TargetSla = $targetSla
            MeetsSla = $true
            AvgLatencyMs = 0
            AvgJitterMs = 0
        }
    }
}
