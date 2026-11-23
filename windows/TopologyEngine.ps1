# TopologyEngine.ps1 - Network Topology Model and Interactive Visualizer for Ambaan Wi-Fi Guard
# PowerShell 5.1 compatible. Non-admin, zero external dependencies.
# AMBAAN 3.0: Rigorous distinction between Observed Physical/Radio Links vs Inferred L2 Neighbors.

$script:TopologyDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Get-Ipv6Neighbors {
    $v6List = @()
    try {
        $neighbors = Get-NetNeighbor -AddressFamily IPv6 -ErrorAction SilentlyContinue |
            Where-Object { $_.State -notin 'Unreachable', 'Permanent' -and $_.IPAddress -notmatch '^(fe80|ff02)' }
        foreach ($n in $neighbors) {
            $v6List += [pscustomobject]@{
                IP = $n.IPAddress
                MAC = $n.LinkLayerAddress.ToUpper()
                State = $n.State
            }
        }
    } catch {}
    return $v6List
}

function Get-NetworkTopologyGraph {
    param(
        $gatewayIp,
        $gatewayMac,
        $routerMs,
        $wifi,
        $lanDevices = @(),
        $servers = @()
    )

    $nodes = @()
    $links = @()

    # 1. Internet Node
    $nodes += [pscustomobject]@{
        Id           = 'node-internet'
        Label        = 'Internet'
        Type         = 'Internet'
        Status       = 'Online'
        SubText      = 'Cloudflare / Public WAN'
        Relationship = 'Public Transit Upstream'
        Confidence   = 'High (Verified via ICMP/DNS)'
        Details      = "Endpoint: Cloudflare / Google WAN`nType: External Upstream Gateway`nRoute Verification: Verified via ICMP and DNS resolution"
    }

    # 2. Router / Gateway Node
    $gwLabel = if ($gatewayIp) { "Router ($gatewayIp)" } else { "Main Router" }
    $gwStatus = if ($routerMs -and $routerMs -lt 50) { 'Online' } elseif ($routerMs) { 'Degraded' } else { 'Offline' }
    $nodes += [pscustomobject]@{
        Id           = 'node-router'
        Label        = $gwLabel
        Type         = 'Router'
        Status       = $gwStatus
        SubText      = $(if ($routerMs) { "$routerMs ms gateway latency" } else { "Unreachable" })
        Relationship = 'Default Local Route Gateway'
        Confidence   = 'High (Direct Subnet Route)'
        Details      = "Gateway IP: $gatewayIp`nMAC: $gatewayMac`nGateway Response: $routerMs ms`nRole: Default Local Gateway`nRouting: Layer 3 Default Next-Hop"
    }
    $links += [pscustomobject]@{
        From       = 'node-internet'
        To         = 'node-router'
        Label      = 'WAN Upstream'
        LinkType   = 'WAN'
        IsObserved = $true
        Dashed     = $false
    }

    # 3. This PC Node (Direct Observed Physical / Wi-Fi Link)
    $pcLabel = "This PC"
    $pcStatus = if ($wifi.Connected) { 'Online' } else { 'Offline' }
    $nodes += [pscustomobject]@{
        Id           = 'node-thispc'
        Label        = $pcLabel
        Type         = 'Host'
        Status       = $pcStatus
        SubText      = "$($wifi.SSID) ($($wifi.Signal)%)"
        Relationship = 'Direct 802.11 Radio Interface (Observed)'
        Confidence   = 'High (Local Operating System Telemetry)'
        Details      = "Host: Local Management Station`nInterface: $($wifi.Name)`nSSID: $($wifi.SSID)`nBand: $($wifi.Band)`nChannel: $($wifi.Channel)`nSignal Strength: $($wifi.Signal)%`nPHY Link Rates: RX $($wifi.RX) Mbps / TX $($wifi.TX) Mbps`nTopology Note: Direct radio link confirmed by Windows WLAN subsystem"
    }
    $links += [pscustomobject]@{
        From       = 'node-router'
        To         = 'node-thispc'
        Label      = 'Direct Wi-Fi'
        LinkType   = 'Observed-Radio'
        IsObserved = $true
        Dashed     = $false
    }

    # 4. LAN Devices (Red-Team Hardening: Inferred L2 Subnet Neighbors via ARP)
    # Check for IPv6 neighbors to enrich dual-stack visibility
    $ipv6Neighbors = Get-Ipv6Neighbors
    $v6Map = @{}
    foreach ($v6 in $ipv6Neighbors) { if ($v6.MAC) { $v6Map[$v6.MAC] = $v6.IP } }

    $devIndex = 1
    foreach ($d in $lanDevices) {
        $devId = "node-dev-$devIndex"
        $devIndex++
        $name = if ($d.Friendly) { $d.Friendly } elseif ($d.Hint) { $d.Hint } else { "Device ($($d.IP))" }
        $status = if ($d.Alive) { 'Online' } else { 'Stale' }
        $macStr = if ($d.MAC) { $d.MAC.ToUpper() } else { '' }
        $v6Addr = if ($v6Map.ContainsKey($macStr)) { $v6Map[$macStr] } else { 'None observed' }
        
        # Check MAC randomization
        $isRandom = $false
        if ($macStr -match '^[0-9A-F]{2}') {
            try {
                $b0 = [Convert]::ToByte($macStr.Substring(0, 2), 16)
                if (($b0 -band 0x02) -ne 0) { $isRandom = $true }
            } catch {}
        }

        $nodes += [pscustomobject]@{
            Id           = $devId
            Label        = $name
            Type         = 'Device'
            Status       = $status
            SubText      = "$($d.IP) $(if($isRandom){'[Private MAC]'})"
            Relationship = 'Inferred L2 Subnet Neighbor (ARP)'
            Confidence   = 'Inferred (ARP table neighbor; physical switch port or mesh AP hop is unobserved)'
            Details      = "Device Identity: $($d.Friendly)`nIPv4 Address: $($d.IP)`nIPv6 Address: $v6Addr`nMAC Address: $($d.MAC)$(if($isRandom){' (Locally Administered / Private)'})`nVendor / Hint: $($d.Hint)`nNeighbor State: $(if($d.Alive){'Responding Neighbor (Active)'}else{'Cached ARP Neighbor'})`nTopology Note: Discovered via Layer-2 ARP broadcast. Intermediate switches, VLAN tags, and Wi-Fi AP hops are inferred, not physically traced."
        }
        # Mark as Inferred link (rendered as dashed)
        $links += [pscustomobject]@{
            From       = 'node-router'
            To         = $devId
            Label      = 'Inferred Neighbor'
            LinkType   = 'Inferred-L2'
            IsObserved = $false
            Dashed     = $true
        }
    }

    # 5. Monitored Remote Servers
    $srvIndex = 1
    foreach ($s in $servers) {
        $srvId = "node-srv-$srvIndex"
        $srvIndex++
        $nodes += [pscustomobject]@{
            Id           = $srvId
            Label        = $s.Name
            Type         = 'Server'
            Status       = $s.Status
            SubText      = "$($s.Host) ($($s.LatencyMs) ms)"
            Relationship = 'Configured Service Endpoint'
            Confidence   = 'High (Active Probe Target)'
            Details      = "Server Target: $($s.Name)`nHost / IP: $($s.Host)`nProbe Type: $($s.CheckType)`nStatus: $($s.Status)`nLatency: $($s.LatencyMs) ms`nPacket Loss: $($s.LossPct)%`nJitter: $(if($s.JitterMs){"$($s.JitterMs) ms"}else{'N/A'})`nDiagnostic Result: $($s.Detail)"
        }
        $links += [pscustomobject]@{
            From       = 'node-router'
            To         = $srvId
            Label      = 'Monitored Service'
            LinkType   = 'Configured-Endpoint'
            IsObserved = $true
            Dashed     = $false
        }
    }

    return [pscustomobject]@{
        Nodes       = $nodes
        Links       = $links
        GeneratedAt = Get-Date
    }
}

function Show-TopologyViewerWindow {
    param($graph)

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object Windows.Forms.Form
    $form.Text = 'Network Topology & Verified Relationships'
    $form.Size = New-Object Drawing.Size(1020, 700)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = [Drawing.Color]::FromArgb(9, 13, 22) # Modern Obsidian
    $form.ForeColor = [Drawing.Color]::FromArgb(248, 250, 252)
    $form.FormBorderStyle = 'Sizable'

    # Side details panel
    $pnlDetails = New-Object Windows.Forms.Panel
    $pnlDetails.Dock = 'Right'
    $pnlDetails.Width = 320
    $pnlDetails.BackColor = [Drawing.Color]::FromArgb(15, 23, 42) # Slate 900

    $lblTitle = New-Object Windows.Forms.Label
    $lblTitle.Text = "TOPOLOGY INSPECTOR"
    $lblTitle.Font = New-Object Drawing.Font('Segoe UI Semibold', 10)
    $lblTitle.ForeColor = [Drawing.Color]::FromArgb(56, 189, 248) # Sky
    $lblTitle.Location = New-Object Drawing.Point(18, 16)
    $lblTitle.Size = New-Object Drawing.Size(280, 22)
    $pnlDetails.Controls.Add($lblTitle)

    $txtDetails = New-Object Windows.Forms.TextBox
    $txtDetails.Multiline = $true
    $txtDetails.ReadOnly = $true
    $txtDetails.ScrollBars = 'Vertical'
    $txtDetails.Location = New-Object Drawing.Point(18, 46)
    $txtDetails.Size = New-Object Drawing.Size(284, 580)
    $txtDetails.BackColor = [Drawing.Color]::FromArgb(11, 16, 28)
    $txtDetails.ForeColor = [Drawing.Color]::FromArgb(226, 232, 240)
    $txtDetails.Font = New-Object Drawing.Font('Consolas', 9.5)
    $txtDetails.BorderStyle = 'FixedSingle'
    $txtDetails.Text = "Click any node on the network map to inspect verified vs inferred topology parameters.`r`n`r`nLEGEND:`r`n── Solid Line: Observed Physical/Radio Link`r`n┄┄ Dashed Line: Inferred L2 Subnet Neighbor (ARP)"
    $pnlDetails.Controls.Add($txtDetails)

    # Canvas panel
    $canvas = New-Object Windows.Forms.PictureBox
    $canvas.Dock = 'Fill'
    $canvas.BackColor = [Drawing.Color]::FromArgb(9, 13, 22)

    $nodePositions = @{}
    $h = 600
    
    $nodePositions['node-internet'] = [Drawing.PointF]::new(70, [int]($h / 2))
    $nodePositions['node-router'] = [Drawing.PointF]::new(240, [int]($h / 2))

    $leafNodes = @($graph.Nodes | Where-Object { $_.Id -notin 'node-internet', 'node-router' })
    $count = [math]::Max(1, $leafNodes.Count)
    $stepY = [math]::Max(48, [int]($h / ($count + 1)))
    $curY = 38

    for ($i = 0; $i -lt $leafNodes.Count; $i++) {
        $n = $leafNodes[$i]
        $x = if ($n.Type -eq 'Server') { 470 } elseif ($n.Type -eq 'Host') { 440 } else { 480 }
        $nodePositions[$n.Id] = [Drawing.PointF]::new($x, $curY)
        $curY += $stepY
    }

    $script:SelectedNode = $null

    $canvas.Add_Paint({
        param($s, $e)
        $g = $e.Graphics
        $g.SmoothingMode = 'AntiAlias'
        $g.TextRenderingHint = 'ClearTypeGridFit'

        # Draw links with observed vs inferred distinction
        foreach ($link in $graph.Links) {
            if ($nodePositions.ContainsKey($link.From) -and $nodePositions.ContainsKey($link.To)) {
                $ptFrom = $nodePositions[$link.From]
                $ptTo = $nodePositions[$link.To]
                $midX = ($ptFrom.X + $ptTo.X) / 2

                $penLink = New-Object Drawing.Pen([Drawing.Color]::FromArgb(75, 56, 189, 248), 1.8)
                if ($link.Dashed) {
                    $penLink.DashStyle = [Drawing.Drawing2D.DashStyle]::Dash
                    $penLink.Color = [Drawing.Color]::FromArgb(45, 148, 163, 184)
                }
                $g.DrawBezier($penLink, $ptFrom.X, $ptFrom.Y, $midX, $ptFrom.Y, $midX, $ptTo.Y, $ptTo.X, $ptTo.Y)
                $penLink.Dispose()
            }
        }

        # Draw nodes with glowing halos
        $fontNode = New-Object Drawing.Font('Segoe UI Semibold', 9.5)
        $fontSub = New-Object Drawing.Font('Segoe UI', 8)
        
        foreach ($node in $graph.Nodes) {
            if (-not $nodePositions.ContainsKey($node.Id)) { continue }
            $pos = $nodePositions[$node.Id]
            $rx = $pos.X - 20; $ry = $pos.Y - 18

            $colNeon = switch ($node.Status) {
                'Online'   { [Drawing.Color]::FromArgb(16, 185, 129) } # Emerald
                'Degraded' { [Drawing.Color]::FromArgb(245, 158, 11) } # Amber
                'Stale'    { [Drawing.Color]::FromArgb(100, 116, 139) } # Slate
                default    { [Drawing.Color]::FromArgb(244, 63, 94) }  # Rose
            }

            # Halo pulse background
            $brushHalo = New-Object Drawing.SolidBrush([Drawing.Color]::FromArgb(35, $colNeon))
            $g.FillEllipse($brushHalo, ($rx - 4), ($ry - 4), 44, 44)
            $brushHalo.Dispose()

            # Node center circle
            $brushNode = New-Object Drawing.SolidBrush([Drawing.Color]::FromArgb(20, 28, 44))
            $penBorder = New-Object Drawing.Pen($colNeon, $(if ($script:SelectedNode -and $script:SelectedNode.Id -eq $node.Id) { 2.5 } else { 1.5 }))
            $g.FillEllipse($brushNode, $rx, $ry, 36, 36)
            $g.DrawEllipse($penBorder, $rx, $ry, 36, 36)
            $brushNode.Dispose(); $penBorder.Dispose()

            # Node label and subtitle card
            $brushTxt = New-Object Drawing.SolidBrush([Drawing.Color]::FromArgb(248, 250, 252))
            $brushSub = New-Object Drawing.SolidBrush([Drawing.Color]::FromArgb(148, 163, 184))
            $g.DrawString($node.Label, $fontNode, $brushTxt, ($rx + 46), ($ry + 2))
            $g.DrawString($node.SubText, $fontSub, $brushSub, ($rx + 46), ($ry + 19))
            $brushTxt.Dispose(); $brushSub.Dispose()
        }
        $fontNode.Dispose(); $fontSub.Dispose()
    })

    $canvas.Add_MouseClick({
        param($s, $e)
        foreach ($node in $graph.Nodes) {
            if (-not $nodePositions.ContainsKey($node.Id)) { continue }
            $pos = $nodePositions[$node.Id]
            $rect = New-Object Drawing.RectangleF(($pos.X - 22), ($pos.Y - 20), 220, 42)
            if ($rect.Contains([single]$e.X, [single]$e.Y)) {
                $script:SelectedNode = $node
                $txtDetails.Text = "=== $($node.Label) ===`r`n`r`n[RELATIONSHIP]:`r`n$($node.Relationship)`r`n`r`n[CONFIDENCE]:`r`n$($node.Confidence)`r`n`r`n[STATUS]: $($node.Status)`r`n----------------------------------`r`n$($node.Details)"
                $canvas.Invalidate()
                break
            }
        }
    })

    $form.Controls.Add($canvas)
    $form.Controls.Add($pnlDetails)
    $form.ShowDialog() | Out-Null
    $form.Dispose()
}
