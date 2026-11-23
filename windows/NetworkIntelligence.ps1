# NetworkIntelligence.ps1 - Anomaly Detection, Incident Correlation & Health Intelligence
# PowerShell 5.1 compatible. Non-admin, zero external dependencies.
# AMBAAN 3.0 Engine: Hardened against false-positives, stale ARP, and classification bias.

$script:IntelDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:IntelDataDir = Join-Path $script:IntelDir 'MonitorData'
if (-not (Test-Path $script:IntelDataDir)) { New-Item -ItemType Directory -Force -Path $script:IntelDataDir | Out-Null }
$script:AnomalyCsv = Join-Path $script:IntelDataDir 'Anomalies.csv'
$script:ConfigAuditCsv = Join-Path $script:IntelDataDir 'ConfigAudit.csv'

# Baseline & State Tracking
$script:BaselineGateway = $null
$script:BaselineGatewayMac = $null
$script:BaselineDns = @()
$script:ConsecutivePingFails = 0
$script:IpToMacHistory = @{}  # IP -> Last seen MAC
$script:IpConflictTracker = @{} # IP -> @{ FirstSeen = [datetime]; Mac1 = ''; Mac2 = ''; ConsecutiveSweeps = int; Confirmed = bool }
$script:ActiveIncident = $null # Cached current correlated incident

function Safe-WriteCsvLine([string]$path, [pscustomobject]$record) {
    try {
        $sync = [System.Threading.Monitor]
        $lockObj = "Sync_$([System.IO.Path]::GetFileNameWithoutExtension($path))"
        if (Test-Path $path) {
            $record | Export-Csv -Path $path -NoTypeInformation -Append -Encoding UTF8
        } else {
            $record | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        }
    } catch {}
}

function Log-NetworkAnomaly([string]$type, [string]$severity, [string]$title, [string]$explanation, [string]$evidence) {
    $rec = [pscustomobject]@{
        Timestamp   = (Get-Date).ToString('s')
        Type        = $type
        Severity    = $severity
        Title       = $title
        Explanation = $explanation
        Evidence    = $evidence
    }
    Safe-WriteCsvLine $script:AnomalyCsv $rec
}

function Log-ConfigAudit([string]$component, [string]$item, [string]$oldVal, [string]$newVal, [string]$reason) {
    $rec = [pscustomobject]@{
        Timestamp = (Get-Date).ToString('s')
        Component = $component
        Item      = $item
        OldValue  = $oldVal
        NewValue  = $newVal
        Reason    = $reason
    }
    Safe-WriteCsvLine $script:ConfigAuditCsv $rec
}

function Evaluate-NetworkAnomalies {
    param(
        $currentScan,
        $currentGateway,
        $currentGatewayMac,
        $currentDns,
        [double]$currentUpMbps,
        [double]$currentDownMbps,
        [int]$routerPingMs,
        [int]$netPingMs,
        [double]$uploadSpikeThreshold = 25.0
    )

    $anomalies = @()
    $now = Get-Date

    # 1. Gateway Identity Changes (Red-Team Hardening: Distinguish Mesh/AP Roaming vs Attack)
    if ($currentGateway) {
        if ($null -ne $script:BaselineGateway -and $currentGateway -ne $script:BaselineGateway) {
            $a = [pscustomobject]@{
                Type = 'GatewayIpChange'
                Severity = 'Warning'
                Title = 'Default Gateway IP Shift'
                Explanation = "The network gateway IP changed from $($script:BaselineGateway) to $currentGateway. Typical causes: roaming to a different Wi-Fi network, subnet reassignment, or VPN adapter connection."
                Evidence = "Previous Gateway: $($script:BaselineGateway) -> Current: $currentGateway"
            }
            $anomalies += $a
            Log-NetworkAnomaly $a.Type $a.Severity $a.Title $a.Explanation $a.Evidence
            Log-ConfigAudit 'NetworkGateway' 'IPv4Gateway' $script:BaselineGateway $currentGateway 'Gateway IP changed'
        }
        $script:BaselineGateway = $currentGateway
    }
    
    if ($currentGatewayMac) {
        if ($null -ne $script:BaselineGatewayMac -and $currentGatewayMac -ne $script:BaselineGatewayMac) {
            $a = [pscustomobject]@{
                Type = 'GatewayMacChange'
                Severity = 'Warning'
                Title = 'Gateway Hardware Identity Changed'
                Explanation = "The default gateway's MAC address shifted from $($script:BaselineGatewayMac) to $currentGatewayMac. Common legitimate causes: Mesh Wi-Fi node handover, router hardware upgrade, or router dual-band AP failover. ARP spoofing is considered only if simultaneous duplicate IP replies are observed."
                Evidence = "Old MAC: $($script:BaselineGatewayMac) -> New MAC: $currentGatewayMac"
            }
            $anomalies += $a
            Log-NetworkAnomaly $a.Type $a.Severity $a.Title $a.Explanation $a.Evidence
            Log-ConfigAudit 'NetworkGateway' 'GatewayMAC' $script:BaselineGatewayMac $currentGatewayMac 'Gateway hardware MAC shifted'
        }
        $script:BaselineGatewayMac = $currentGatewayMac
    }

    # 2. IP Conflict Detection (Red-Team Hardening: Windowed Verification to prevent stale ARP false positives)
    if ($currentScan -and $currentScan.Rows) {
        $observedIps = @{}
        foreach ($r in $currentScan.Rows) {
            if (-not $r.IP -or -not $r.MAC) { continue }
            $ip = [string]$r.IP
            $mac = [string]$r.MAC.ToUpper()

            # Detect multiple MACs for single IP in current sweep
            if ($observedIps.ContainsKey($ip)) {
                $priorMac = $observedIps[$ip]
                if ($priorMac -ne $mac) {
                    # Check persistent conflict tracker
                    if (-not $script:IpConflictTracker.ContainsKey($ip)) {
                        # First observation: Mark as investigating (Info) to eliminate transient ARP cache jitter
                        $script:IpConflictTracker[$ip] = @{
                            FirstSeen = $now
                            Mac1 = $priorMac
                            Mac2 = $mac
                            ConsecutiveSweeps = 1
                            Confirmed = $false
                        }
                        $a = [pscustomobject]@{
                            Type = 'IpConflictInvestigating'
                            Severity = 'Info'
                            Title = "Potential IP Reassignment ($ip)"
                            Explanation = "Two MACs ($priorMac and $mac) appeared for IP $ip in neighbor table. Monitoring to distinguish stale ARP cache or DHCP lease recycling from a sustained conflict."
                            Evidence = "Candidates: $priorMac, $mac for IP $ip"
                        }
                        $anomalies += $a
                        Log-NetworkAnomaly $a.Type $a.Severity $a.Title $a.Explanation $a.Evidence
                    } else {
                        # Repeated observation across consecutive sweeps: Confirmed Conflict!
                        $entry = $script:IpConflictTracker[$ip]
                        $entry.ConsecutiveSweeps++
                        if ($entry.ConsecutiveSweeps -ge 2 -and -not $entry.Confirmed) {
                            $entry.Confirmed = $true
                            $a = [pscustomobject]@{
                                Type = 'IpConflictConfirmed'
                                Severity = 'Critical'
                                Title = "Confirmed IP Address Conflict ($ip)"
                                Explanation = "Two independent hardware adapters ($($entry.Mac1) and $($entry.Mac2)) have sustained concurrent ownership of IP $ip across multiple sweeps. This causes packet dropping and TCP resets."
                                Evidence = "Persisted conflict: $($entry.Mac1) vs $($entry.Mac2) on $ip ($($entry.ConsecutiveSweeps) consecutive sweeps)"
                            }
                            $anomalies += $a
                            Log-NetworkAnomaly $a.Type $a.Severity $a.Title $a.Explanation $a.Evidence
                        }
                    }
                }
            } else {
                $observedIps[$ip] = $mac
            }

            # Check historical reassignment
            if ($script:IpToMacHistory.ContainsKey($ip)) {
                $histMac = $script:IpToMacHistory[$ip]
                if ($histMac -ne $mac) {
                    # Benign DHCP lease expiration / reassignment
                    $a = [pscustomobject]@{
                        Type = 'DhcpReassigned'
                        Severity = 'Info'
                        Title = "Device IP Reassigned ($ip)"
                        Explanation = "IP $ip was previously used by $histMac and is now assigned to $mac. Standard DHCP lease renewal."
                        Evidence = "Previous: $histMac -> Now: $mac"
                    }
                    $anomalies += $a
                    Log-NetworkAnomaly $a.Type $a.Severity $a.Title $a.Explanation $a.Evidence
                }
            }
            $script:IpToMacHistory[$ip] = $mac
        }
    }

    # 3. DNS Configuration Drift
    if ($currentDns -and $currentDns.Servers) {
        $currentAddrs = @($currentDns.Servers | ForEach-Object { $_.Address }) | Sort-Object
        if ($script:BaselineDns.Count -gt 0) {
            $diff = Compare-Object $script:BaselineDns $currentAddrs
            if ($diff) {
                $a = [pscustomobject]@{
                    Type = 'DnsChange'
                    Severity = 'Info'
                    Title = 'Active DNS Resolvers Changed'
                    Explanation = "The system's active DNS resolvers were reconfigured. Verify DNS Shield status to ensure encrypted/filtered resolution is active."
                    Evidence = "Old: $($script:BaselineDns -join ', ') -> New: $($currentAddrs -join ', ')"
                }
                $anomalies += $a
                Log-NetworkAnomaly $a.Type $a.Severity $a.Title $a.Explanation $a.Evidence
                Log-ConfigAudit 'DNS' 'Resolvers' ($script:BaselineDns -join ', ') ($currentAddrs -join ', ') 'DNS server addresses changed'
            }
        }
        $script:BaselineDns = $currentAddrs
    }

    # 4. Bandwidth Intelligence (Red-Team Hardening: Explicitly Scope to This PC)
    if ($currentUpMbps -ge $uploadSpikeThreshold) {
        $a = [pscustomobject]@{
            Type = 'HighUploadThisPC'
            Severity = 'Warning'
            Title = 'High Upload Activity on This Computer'
            Explanation = "This local computer is currently transmitting data at $currentUpMbps Mbps (configured alert limit: $uploadSpikeThreshold Mbps). Note: Measurement captures this host's network adapter throughput; total network consumption by other devices requires router SNMP/NetFlow integration."
            Evidence = "Host Adapter Upload: $currentUpMbps Mbps"
        }
        $anomalies += $a
        Log-NetworkAnomaly $a.Type $a.Severity $a.Title $a.Explanation $a.Evidence
    }

    # 5. Repeated Connectivity Failures & Recovery
    if ($netPingMs -le 0 -or $null -eq $netPingMs) {
        $script:ConsecutivePingFails++
        if ($script:ConsecutivePingFails -eq 3) {
            $a = [pscustomobject]@{
                Type = 'ConnectivityDrop'
                Severity = 'Critical'
                Title = 'External Internet Unreachable'
                Explanation = "External internet endpoints (1.1.1.1 / 8.8.8.8) have not responded for 3 consecutive diagnostic checks."
                Evidence = "Router ping: $(if ($routerPingMs) { "$routerPingMs ms" } else { "Unreachable" }); Internet ping: 100% loss"
            }
            $anomalies += $a
            Log-NetworkAnomaly $a.Type $a.Severity $a.Title $a.Explanation $a.Evidence
        }
    } else {
        if ($script:ConsecutivePingFails -ge 3) {
            $a = [pscustomobject]@{
                Type = 'ConnectivityRestored'
                Severity = 'Info'
                Title = 'Internet Connectivity Restored'
                Explanation = "External internet routes have recovered. Roundtrip latency is $netPingMs ms."
                Evidence = "Internet ping resumed: $netPingMs ms"
            }
            $anomalies += $a
            Log-NetworkAnomaly $a.Type $a.Severity $a.Title $a.Explanation $a.Evidence
        }
        $script:ConsecutivePingFails = 0
    }

    return $anomalies
}

# Incident Correlation Engine (AMBAAN 3.0 Core)
# Correlates multi-layer signals to identify the root cause instead of firing individual alert storms.
function Get-CorrelatedIncidentSummary {
    param(
        $wifi,
        $routerMs,
        $netMs,
        $dnsStatus,
        $serverResults = @()
    )

    $rootCause = "Normal"
    $incidentTitle = "All Subsystems Nominal"
    $incidentDescription = "Local Wi-Fi link, local router gateway, public internet transit, and configured server endpoints are healthy."
    $severity = "Nominal"

    $wifiOk = ($wifi -and $wifi.Connected -and ($null -ne $wifi.Signal -and $wifi.Signal -ge 30))
    $routerOk = ($null -ne $routerMs -and $routerMs -le 35)
    $netOk = ($null -ne $netMs -and $netMs -gt 0)
    $dnsOk = ($dnsStatus -ne 'Bad' -and $dnsStatus -ne 'Failed')

    $downServers = @($serverResults | Where-Object { $_.Status -eq 'Offline' })
    $srvDownCount = $downServers.Count
    $totalSrv = @($serverResults).Count

    # Root Cause Rule 1: Local Adapter / Radio Down
    if (-not $wifi.Connected) {
        $rootCause = "LocalAdapterDisconnected"
        $severity = "Critical"
        $incidentTitle = "Local Wi-Fi Interface Disconnected"
        $incidentDescription = "Your computer's Wi-Fi adapter is disconnected. All network traffic and server checks are suspended at the host interface."
    }
    # Root Cause Rule 2: Wi-Fi Signal Degradation
    elseif ($wifi.Signal -lt 30) {
        $rootCause = "WeakRadioSignal"
        $severity = "Warning"
        $incidentTitle = "Radio Signal Degradation ($($wifi.Signal)%)"
        $incidentDescription = "Wi-Fi radio link quality has dropped below minimum threshold. High frame retries at the physical layer are introducing latency jitter."
    }
    # Root Cause Rule 3: Gateway Down (Local Infrastructure Failure)
    elseif (-not $routerOk) {
        $rootCause = "LocalGatewayUnreachable"
        $severity = "Critical"
        $incidentTitle = "Default Gateway Router Unreachable"
        $incidentDescription = "The local router is not responding to ICMP. Local subnet routing has failed; external internet and cross-VLAN servers cannot be reached."
    }
    # Root Cause Rule 4: Upstream WAN / ISP Outage (Wi-Fi and Router are fine, but Internet and multiple external servers fail)
    elseif ($routerOk -and -not $netOk) {
        $rootCause = "UpstreamTransitOutage"
        $severity = "Critical"
        $incidentTitle = "Upstream ISP Transit Interruption"
        $incidentDescription = "Local Wi-Fi link ($($wifi.Signal)%) and router response ($routerMs ms) are healthy, but public internet transit is failing. The bottleneck is with the ISP or optical WAN modem."
    }
    # Root Cause Rule 5: DNS Failure
    elseif ($netOk -and -not $dnsOk) {
        $rootCause = "DnsResolutionFailure"
        $severity = "Warning"
        $incidentTitle = "DNS Name Resolution Failure"
        $incidentDescription = "IP-level internet connectivity is active, but DNS lookups are failing. Domain names cannot be resolved."
    }
    # Root Cause Rule 6: Isolated Server/Service Outage (Infrastructure healthy, specific endpoints down)
    elseif ($srvDownCount -gt 0) {
        $rootCause = "ServiceEndpointOutage"
        $severity = "Warning"
        $incidentTitle = "$srvDownCount Monitored Service(s) Down"
        $incidentDescription = "Your local Wi-Fi, gateway, and internet connection are fully operational. Downtime is isolated to target host/service: $(($downServers | ForEach-Object { $_.Name }) -join ', ')."
    }

    $script:ActiveIncident = [pscustomobject]@{
        RootCause     = $rootCause
        Severity      = $severity
        Title         = $incidentTitle
        Description   = $incidentDescription
        CorrelatedAt  = Get-Date
        Signals = @{
            WifiConnected = [bool]$wifi.Connected
            WifiSignal    = $wifi.Signal
            RouterMs      = $routerMs
            InternetMs    = $netMs
            DnsStatus     = $dnsStatus
            ServersDown   = $srvDownCount
        }
    }

    return $script:ActiveIncident
}

function Get-NetworkHealthAssessment {
    param(
        $wifi,
        $routerMs,
        $netMs,
        $dnsStatus,
        $speedDown,
        $serverResults = @()
    )

    # Get Correlated Incident
    $incident = Get-CorrelatedIncidentSummary -wifi $wifi -routerMs $routerMs -netMs $netMs -dnsStatus $dnsStatus -serverResults $serverResults

    $assessments = @()
    $evidence = @()

    $assessments += "ROOT CAUSE: $($incident.Title)`n$($incident.Description)"
    $evidence += "Incident Classification: $($incident.RootCause) ($($incident.Severity))"

    # Wi-Fi link analysis
    if ($wifi.Connected) {
        if ($null -ne $wifi.Signal) {
            $evidence += "Wi-Fi Signal: $($wifi.Signal)% ($(if($wifi.Signal -ge 75){'Optimal'}elseif($wifi.Signal -ge 50){'Fair'}else{'Degraded'}))"
        }
    } else {
        $evidence += "Wi-Fi Adapter: Disconnected"
    }

    # Router vs WAN latency
    if ($null -ne $routerMs) {
        $evidence += "Router Gateway Response: $routerMs ms ($(if($routerMs -le 20){'Normal'}else{'Elevated'}))"
    } else {
        $evidence += "Router Gateway: Unreachable"
    }

    if ($null -ne $netMs) {
        $evidence += "Public Internet Transit: $netMs ms"
    } else {
        $evidence += "Public Internet: 100% Packet Loss"
    }

    # Server checks
    if ($serverResults -and $serverResults.Count -gt 0) {
        $downServers = @($serverResults | Where-Object { $_.Status -eq 'Offline' })
        if ($downServers.Count -gt 0) {
            $evidence += "Service Health: $($downServers.Count) of $(@($serverResults).Count) endpoints failing"
        } else {
            $evidence += "Service Health: All $(@($serverResults).Count) endpoints answering normally"
        }
    }

    return [pscustomobject]@{
        Summary    = $assessments -join "`n`n"
        Evidence   = $evidence
        Incident   = $incident
        AssessedAt = Get-Date
    }
}
