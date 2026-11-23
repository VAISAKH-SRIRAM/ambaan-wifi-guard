#!/usr/bin/env python3
"""
Ambaan 3.0 Network Intelligence & Diagnostic Analyzer (Ubuntu Linux)
Comprehensive Network Diagnostics, Server Health Monitoring, Topology Generation,
and Obsidian Glass HTML Report Generator.
Zero external CDNs or external pip dependencies.
"""

import datetime
import html
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request

# Local module imports
from server_monitor import load_servers, probe_all_servers
from network_intelligence import track_gateway_identity, verify_ip_conflicts, measure_this_pc_bandwidth, correlate_incidents
from topology_engine import build_network_topology_svg

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(SCRIPT_DIR, "Reports")
HISTORY_DIR = os.path.join(SCRIPT_DIR, "History")
MONITOR_DATA_DIR = os.path.join(SCRIPT_DIR, "MonitorData")

def ensure_dirs():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(HISTORY_DIR, exist_ok=True)
    os.makedirs(MONITOR_DATA_DIR, exist_ok=True)

def run_cmd(cmd_list, timeout=5):
    """Executes a command and returns stripped stdout, or empty string on error."""
    try:
        res = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return res.stdout.strip()
    except Exception:
        return ""

def get_default_route_and_interface():
    """Identifies default gateway IP and primary network interface."""
    gw_ip = "192.168.1.1"
    iface = "wlan0"
    
    # Try 'ip route show default'
    route_out = run_cmd(["ip", "route", "show", "default"])
    if route_out:
        # default via 192.168.1.1 dev wlan0 proto dhcp metric 600
        m = re.search(r"default\s+via\s+([0-9\.]+)\s+dev\s+([a-zA-Z0-9_\-]+)", route_out)
        if m:
            gw_ip = m.group(1)
            iface = m.group(2)
            return gw_ip, iface
            
    # Fallback to /proc/net/route
    if os.path.exists("/proc/net/route"):
        try:
            with open("/proc/net/route", "r") as f:
                lines = f.readlines()
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    iface = parts[0]
                    # Parse hex IP in little endian
                    h = parts[2]
                    if len(h) == 8:
                        gw_ip = f"{int(h[6:8],16)}.{int(h[4:6],16)}.{int(h[2:4],16)}.{int(h[0:2],16)}"
                    break
        except Exception:
            pass
            
    return gw_ip, iface

def get_interface_ip_and_mac(iface):
    """Retrieves IP and MAC for given interface."""
    this_ip = "127.0.0.1"
    this_mac = "00:00:00:00:00:00"
    
    # Get IP
    addr_out = run_cmd(["ip", "-o", "-4", "addr", "show", iface])
    m = re.search(r"inet\s+([0-9\.]+)/(\d+)", addr_out)
    if m:
        this_ip = m.group(1)
        
    # Get MAC
    mac_file = f"/sys/class/net/{iface}/address"
    if os.path.exists(mac_file):
        try:
            with open(mac_file, "r") as f:
                this_mac = f.read().strip()
        except Exception:
            pass
            
    return this_ip, this_mac

def get_wifi_telemetry(iface):
    """Gathers Wi-Fi metrics (SSID, BSSID, Signal %, Link Speed, Channel)."""
    ssid = "Connected Network"
    bssid = ""
    signal_pct = 78
    bitrate_mbps = 144
    channel = 6
    freq = "2.4 GHz"
    
    # Try nmcli first if installed
    nmcli_out = run_cmd(["nmcli", "-t", "-f", "active,ssid,bssid,signal,chan,freq", "dev", "wifi"])
    for line in nmcli_out.splitlines():
        parts = line.split(":")
        if parts and parts[0] == "yes":
            # yes:MySSID:XX\:XX\:XX\:XX\:XX\:XX:85:6:2437 MHz
            # Note: bssid might contain colons, handle carefully
            idx_signal = -3
            idx_chan = -2
            idx_freq = -1
            if len(parts) >= 6:
                signal_str = parts[idx_signal]
                chan_str = parts[idx_chan]
                freq_str = parts[idx_freq]
                if signal_str.isdigit():
                    signal_pct = int(signal_str)
                if chan_str.isdigit():
                    channel = int(chan_str)
                if "5" in freq_str:
                    freq = "5 GHz"
                # SSID is part 1
                ssid = parts[1] if parts[1] else "Wi-Fi Network"
            break
            
    # Try iw / iwconfig fallback
    iw_out = run_cmd(["iwconfig", iface])
    if iw_out:
        m_essid = re.search(r'ESSID:"([^"]+)"', iw_out)
        if m_essid:
            ssid = m_essid.group(1)
        m_rate = re.search(r'Bit Rate[=:](\d+)', iw_out)
        if m_rate:
            bitrate_mbps = int(m_rate.group(1))
        m_sig = re.search(r'Link Quality=(\d+)/(\d+)', iw_out)
        if m_sig:
            num = int(m_sig.group(1))
            den = int(m_sig.group(2))
            signal_pct = int((num / den) * 100)
            
    # Gateway MAC from neighbor table
    gw_mac = ""
    neigh_out = run_cmd(["ip", "neigh", "show"])
    for line in neigh_out.splitlines():
        if "lladdr" in line:
            parts = line.split()
            if len(parts) >= 5 and "REACHABLE" in line or "DELAY" in line or "STALE" in line:
                gw_mac = parts[4]
                break
                
    return {
        "ssid": ssid,
        "bssid": bssid,
        "signalPct": signal_pct,
        "linkSpeedMbps": bitrate_mbps,
        "channel": channel,
        "band": freq,
        "gatewayMac": gw_mac
    }

def get_dns_servers():
    """Identifies active DNS resolver addresses."""
    resolvers = []
    if os.path.exists("/etc/resolv.conf"):
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.strip().startswith("nameserver"):
                        parts = line.strip().split()
                        if len(parts) > 1:
                            resolvers.append(parts[1])
        except Exception:
            pass
    if not resolvers:
        resolvers = ["8.8.8.8", "1.1.1.1"]
    return resolvers

def measure_ping_metrics(target_host, count=4):
    """Executes ICMP ping and computes RTT min/avg/max and RFC 3550 Jitter."""
    try:
        proc = subprocess.run(["ping", "-c", str(count), "-W", "2", target_host],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8)
        times = [float(m) for m in re.findall(r"time=([\d\.]+)\s*ms", proc.stdout)]
        loss_m = re.search(r"(\d+)%\s*packet loss", proc.stdout)
        loss_pct = int(loss_m.group(1)) if loss_m else (0 if proc.returncode == 0 else 100)
        
        if not times:
            return {
                "online": False,
                "avgRtt": None,
                "minRtt": None,
                "maxRtt": None,
                "jitter": 0.0,
                "packetLoss": loss_pct
            }
            
        avg_rtt = sum(times) / len(times)
        min_rtt = min(times)
        max_rtt = max(times)
        
        # Calculate RFC 3550 Jitter
        jitter = 0.0
        for i in range(1, len(times)):
            d = abs(times[i] - times[i-1])
            jitter += (d - jitter) / 16.0
            
        return {
            "online": True,
            "avgRtt": round(avg_rtt, 2),
            "minRtt": round(min_rtt, 2),
            "maxRtt": round(max_rtt, 2),
            "jitter": round(jitter, 2),
            "packetLoss": loss_pct
        }
    except Exception:
        return {
            "online": False,
            "avgRtt": None,
            "minRtt": None,
            "maxRtt": None,
            "jitter": 0.0,
            "packetLoss": 100
        }

def measure_dns_latency(domain="google.com"):
    """Measures DNS lookup duration."""
    t0 = time.perf_counter()
    try:
        socket.gethostbyname(domain)
        ms = (time.perf_counter() - t0) * 1000.0
        return True, round(ms, 2)
    except Exception:
        return False, None

def get_neighbor_table():
    """Parses local ARP / neighbor cache."""
    neighbors = []
    neigh_out = run_cmd(["ip", "neigh", "show"])
    for line in neigh_out.splitlines():
        # 192.168.1.1 dev wlan0 lladdr 10:da:43:xx:xx:xx REACHABLE
        parts = line.split()
        if len(parts) >= 4 and "lladdr" in parts:
            ip = parts[0]
            mac_idx = parts.index("lladdr") + 1
            if mac_idx < len(parts):
                mac = parts[mac_idx]
                state = parts[-1]
                neighbors.append({
                    "ip": ip,
                    "mac": mac,
                    "state": state
                })
    return neighbors

def generate_obsidian_report(report_data):
    """Builds the comprehensive Obsidian Glass HTML Diagnostic Report."""
    now_str = report_data["timestamp"]
    wifi = report_data["wifi"]
    gw_ping = report_data["gatewayPing"]
    net_ping = report_data["internetPing"]
    dns_res = report_data["dns"]
    servers = report_data["servers"]
    gw_intel = report_data["gatewayIntel"]
    conflicts = report_data["conflicts"]
    bandwidth = report_data["bandwidth"]
    incidents = report_data["incidents"]
    topology_svg = report_data["topologySvg"]
    
    score = 100
    if not gw_ping["online"]:
        score -= 50
    elif gw_ping["avgRtt"] and gw_ping["avgRtt"] > 50:
        score -= 15
    if not net_ping["online"]:
        score -= 30
    elif net_ping["packetLoss"] > 0:
        score -= min(30, net_ping["packetLoss"])
    if wifi["signalPct"] < 50:
        score -= 15
    if conflicts:
        score -= 20
    score = max(5, min(100, score))
    
    grade = "EXCELLENT" if score >= 90 else ("GOOD" if score >= 75 else ("FAIR" if score >= 55 else "DEGRADED"))
    grade_color = "#10b981" if score >= 85 else ("#f59e0b" if score >= 60 else "#ef4444")
    
    # Server rows
    srv_rows = []
    for s in servers:
        s_color = "#10b981" if s.get("status") == "ONLINE" else "#ef4444"
        srv_rows.append(f'''
        <tr class="border-b border-gray-800 hover:bg-gray-800/40 transition">
          <td class="py-3 px-4 font-semibold text-gray-200">{html.escape(s.get('name'))}</td>
          <td class="py-3 px-4 text-gray-400 font-mono text-xs">{html.escape(s.get('host'))}</td>
          <td class="py-3 px-4"><span class="px-2 py-0.5 rounded text-xs bg-gray-800 text-gray-300 font-mono">{s.get('checkType')}</span></td>
          <td class="py-3 px-4 font-bold" style="color:{s_color};">{s.get('status')}</td>
          <td class="py-3 px-4 font-mono text-xs">{s.get('latencyMs', -1)} ms</td>
          <td class="py-3 px-4 font-mono text-xs text-gray-400">{s.get('jitterMs', 0)} ms</td>
          <td class="py-3 px-4 font-mono text-xs font-semibold text-blue-400">{s.get('observedSla', 100)}%</td>
        </tr>
        ''')
    srv_tbody = "".join(srv_rows) if srv_rows else '<tr><td colspan="7" class="py-4 text-center text-gray-500">No servers configured</td></tr>'
    
    # Incident cards
    inc_html = []
    if incidents:
        for inc in incidents:
            inc_html.append(f'''
            <div class="p-4 rounded-xl border border-red-500/30 bg-red-950/20 mb-4">
              <div class="flex items-center justify-between mb-2">
                <span class="text-sm font-bold text-red-400 uppercase tracking-wider">{html.escape(inc.get('title'))}</span>
                <span class="text-xs px-2 py-0.5 rounded bg-red-500/20 text-red-300 font-semibold">{inc.get('severity')}</span>
              </div>
              <p class="text-xs text-gray-300 mb-2">{html.escape(inc.get('rootCause'))}</p>
              <div class="text-xs text-gray-400 font-mono">Impact: {html.escape(inc.get('impact'))}</div>
            </div>
            ''')
    else:
        inc_html.append('''
        <div class="p-4 rounded-xl border border-emerald-500/20 bg-emerald-950/10 text-emerald-300 text-xs flex items-center gap-2">
          <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
          No active network incidents detected. All monitored routes operational.
        </div>
        ''')
    incidents_body = "".join(inc_html)
    
    # IP Conflict alert
    conflict_banner = ""
    if conflicts:
        conflict_banner = f'''
        <div class="p-4 rounded-xl border border-amber-500/30 bg-amber-950/20 mb-6">
          <div class="text-amber-400 font-bold text-sm mb-1">Temporal IP Conflict Verified ({len(conflicts)} active)</div>
          <div class="text-xs text-gray-300">Multiple hardware MACs observed repeatedly claiming the same IP across the observation window.</div>
        </div>
        '''

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Ambaan 3.0 Diagnostic Dossier (Ubuntu Linux)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    *, ::before, ::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: #030712;
      color: #f3f4f6;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.5;
      padding: 2rem 1rem;
    }}
    .max-w-7xl {{ max-width: 80rem; margin: 0 auto; }}
    .glass-panel {{
      background: rgba(17, 24, 39, 0.75);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 1rem;
      backdrop-filter: blur(12px);
    }}
    .grid-4 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; }}
    .grid-2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 1.5rem; }}
    .nav-btn {{
      background: transparent;
      border: 1px solid rgba(255,255,255,0.1);
      color: #9ca3af;
      padding: 0.5rem 1rem;
      border-radius: 0.5rem;
      cursor: pointer;
      font-size: 0.85rem;
      font-weight: 600;
      transition: all 0.2s;
    }}
    .nav-btn.active, .nav-btn:hover {{
      background: #1f2937;
      color: #ffffff;
      border-color: #38bdf8;
    }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; }}
    th {{ padding: 0.75rem 1rem; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #9ca3af; background: rgba(31, 41, 55, 0.4); }}
    td {{ padding: 0.75rem 1rem; }}
    .tab-content {{ display: none; }}
    .tab-content.active {{ display: block; }}
  </style>
</head>
<body>
  <div class="max-w-7xl">
    <!-- Header -->
    <header class="glass-panel p-6 mb-6 flex flex-wrap justify-between items-center" style="display: flex; justify-content: space-between; align-items: center;">
      <div>
        <div style="display: flex; align-items: center; gap: 0.75rem;">
          <h1 style="font-size: 1.5rem; font-weight: 800; letter-spacing: -0.025em; color: #f8fafc;">AMBAAN 3.0</h1>
          <span style="font-size: 0.75rem; background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); padding: 0.2rem 0.5rem; border-radius: 0.375rem; font-weight: 700;">UBUNTU EDITION</span>
        </div>
        <p style="font-size: 0.875rem; color: #94a3b8; margin-top: 0.25rem;">Industrial Network Intelligence, SLA Telemetry & Topology Engine</p>
      </div>
      <div style="text-align: right;">
        <div style="font-size: 0.75rem; color: #64748b; font-family: monospace;">{now_str}</div>
        <div style="font-size: 0.875rem; font-weight: 700; color: {grade_color}; margin-top: 0.2rem;">HEALTH SCORE: {score}/100 ({grade})</div>
      </div>
    </header>

    {conflict_banner}

    <!-- Key Metrics Ribbon -->
    <div class="grid-4 mb-6" style="margin-bottom: 1.5rem;">
      <div class="glass-panel" style="padding: 1.25rem;">
        <div style="font-size: 0.75rem; text-transform: uppercase; color: #94a3b8; font-weight: 700;">Wi-Fi Signal & Link</div>
        <div style="font-size: 1.5rem; font-weight: 800; color: #38bdf8; margin: 0.25rem 0;">{wifi['signalPct']}% <span style="font-size: 0.85rem; color: #64748b;">({wifi['linkSpeedMbps']} Mbps)</span></div>
        <div style="font-size: 0.75rem; color: #9ca3af;">{html.escape(wifi['ssid'])} • {wifi['band']}</div>
      </div>

      <div class="glass-panel" style="padding: 1.25rem;">
        <div style="font-size: 0.75rem; text-transform: uppercase; color: #94a3b8; font-weight: 700;">Gateway Latency</div>
        <div style="font-size: 1.5rem; font-weight: 800; color: #10b981; margin: 0.25rem 0;">{gw_ping['avgRtt'] or 'TIMEOUT'} <span style="font-size: 0.85rem; color: #64748b;">ms</span></div>
        <div style="font-size: 0.75rem; color: #9ca3af;">Jitter: {gw_ping['jitter']} ms • Loss: {gw_ping['packetLoss']}%</div>
      </div>

      <div class="glass-panel" style="padding: 1.25rem;">
        <div style="font-size: 0.75rem; text-transform: uppercase; color: #94a3b8; font-weight: 700;">This PC Bandwidth</div>
        <div style="font-size: 1.5rem; font-weight: 800; color: #a855f7; margin: 0.25rem 0;">↓{bandwidth['rxRateKbps']} <span style="font-size: 0.85rem; color: #64748b;">KB/s</span></div>
        <div style="font-size: 0.75rem; color: #9ca3af;">↑{bandwidth['txRateKbps']} KB/s • Observed on host</div>
      </div>

      <div class="glass-panel" style="padding: 1.25rem;">
        <div style="font-size: 0.75rem; text-transform: uppercase; color: #94a3b8; font-weight: 700;">DNS Shield & Health</div>
        <div style="font-size: 1.5rem; font-weight: 800; color: #ec4899; margin: 0.25rem 0;">{dns_res['latencyMs'] or 'FAIL'} <span style="font-size: 0.85rem; color: #64748b;">ms</span></div>
        <div style="font-size: 0.75rem; color: #9ca3af;">Primary: {html.escape(report_data['dnsServers'][0] if report_data['dnsServers'] else 'None')}</div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div style="display: flex; gap: 0.5rem; margin-bottom: 1.5rem; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 0.75rem;">
      <button class="nav-btn active" onclick="showTab('tab-topology')">Topology Map</button>
      <button class="nav-btn" onclick="showTab('tab-servers')">Server SLAs</button>
      <button class="nav-btn" onclick="showTab('tab-incidents')">Incident Correlation</button>
      <button class="nav-btn" onclick="showTab('tab-intelligence')">Network Intelligence</button>
    </div>

    <!-- TAB 1: Topology Map -->
    <div id="tab-topology" class="tab-content active">
      <div class="glass-panel" style="padding: 1.5rem; margin-bottom: 1.5rem;">
        <h2 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 0.5rem;">Observed vs Inferred Network Topology</h2>
        <p style="font-size: 0.8rem; color: #94a3b8; margin-bottom: 1rem;">Solid strokes represent verified ARP neighbor relationships. Dashed strokes represent inferred paths.</p>
        <div style="overflow-x: auto;">
          {topology_svg}
        </div>
      </div>
    </div>

    <!-- TAB 2: Server SLAs -->
    <div id="tab-servers" class="tab-content">
      <div class="glass-panel" style="overflow: hidden; margin-bottom: 1.5rem;">
        <div style="padding: 1.25rem; border-bottom: 1px solid rgba(255,255,255,0.08);">
          <h2 style="font-size: 1.1rem; font-weight: 700;">Mission-Critical Server Observability</h2>
          <p style="font-size: 0.8rem; color: #94a3b8;">Continuously monitored ICMP, TCP, and HTTP targets with rolling SLA compliance tracking.</p>
        </div>
        <div style="overflow-x: auto;">
          <table>
            <thead>
              <tr>
                <th>Target Name</th>
                <th>Host / Endpoint</th>
                <th>Check Type</th>
                <th>Status</th>
                <th>Latency</th>
                <th>Jitter</th>
                <th>Observed SLA</th>
              </tr>
            </thead>
            <tbody>
              {srv_tbody}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 3: Incident Correlation -->
    <div id="tab-incidents" class="tab-content">
      <div class="glass-panel" style="padding: 1.5rem; margin-bottom: 1.5rem;">
        <h2 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 0.5rem;">Correlated Incident Timeline</h2>
        <p style="font-size: 0.8rem; color: #94a3b8; margin-bottom: 1.25rem;">Unified root-cause deduction preventing alert floods.</p>
        {incidents_body}
      </div>
    </div>

    <!-- TAB 4: Network Intelligence -->
    <div id="tab-intelligence" class="tab-content">
      <div class="grid-2">
        <div class="glass-panel" style="padding: 1.5rem;">
          <h2 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 0.5rem;">Gateway MAC & Roaming Classification</h2>
          <p style="font-size: 0.8rem; color: #94a3b8; margin-bottom: 1rem;">Distinguishes normal mesh Wi-Fi AP handover from ARP spoofing.</p>
          <div style="background: rgba(0,0,0,0.3); border-radius: 0.5rem; padding: 1rem; font-family: monospace; font-size: 0.8rem;">
            <div>Classification: <strong style="color: #38bdf8;">{gw_intel['classification']}</strong></div>
            <div style="margin-top: 0.5rem; color: #cbd5e1;">{gw_intel['description']}</div>
            <div style="margin-top: 0.5rem; color: #64748b;">Current MAC: {gw_intel['currentMac'] or 'Unknown'}</div>
          </div>
        </div>

        <div class="glass-panel" style="padding: 1.5rem;">
          <h2 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 0.5rem;">Bandwidth Intelligence Scope</h2>
          <p style="font-size: 0.8rem; color: #94a3b8; margin-bottom: 1rem;">Strict separation of host telemetry from router network statistics.</p>
          <div style="background: rgba(0,0,0,0.3); border-radius: 0.5rem; padding: 1rem; font-size: 0.85rem;">
            <div style="color: #34d399; font-weight: 600; margin-bottom: 0.25rem;">[Observed] This PC Host Interface</div>
            <div style="font-size: 0.8rem; color: #cbd5e1;">Cumulative Received: {bandwidth['rxTotalMB']} MB</div>
            <div style="font-size: 0.8rem; color: #cbd5e1;">Cumulative Transmitted: {bandwidth['txTotalMB']} MB</div>
            <div style="font-size: 0.75rem; color: #94a3b8; margin-top: 0.5rem;">Note: Router-wide per-client bandwidth requires SNMP/NetFlow integration. Host monitoring strictly reflects this Ubuntu PC.</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Footer -->
    <footer style="text-align: center; font-size: 0.75rem; color: #64748b; margin-top: 3rem;">
      Ambaan 3.0 Network Intelligence & Security Suite • Developed by Vaisakh Sriram • Original concept & assets by ShiftLogic Labs
    </footer>
  </div>

  <script>
    function showTab(tabId) {{
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
      document.getElementById(tabId).classList.add('active');
      event.currentTarget.classList.add('active');
    }}
  </script>
</body>
</html>
'''
    return html_content

def main():
    print("=================================================================")
    print("  AMBAAN 3.0: Network Intelligence & SLA Engine (Ubuntu Linux)")
    print("=================================================================")
    ensure_dirs()
    
    gw_ip, iface = get_default_route_and_interface()
    this_ip, this_mac = get_interface_ip_and_mac(iface)
    wifi = get_wifi_telemetry(iface)
    dns_servers = get_dns_servers()
    
    print(f"[*] Interface: {iface} ({this_ip})")
    print(f"[*] Gateway:   {gw_ip}")
    print(f"[*] Wi-Fi:     {wifi['ssid']} (Signal: {wifi['signalPct']}%, Rate: {wifi['linkSpeedMbps']} Mbps)")
    print(f"[*] Probing ICMP Gateway latency & RFC 3550 Jitter...")
    gw_ping = measure_ping_metrics(gw_ip, count=4)
    print(f"    -> Gateway Latency: {gw_ping['avgRtt']} ms | Jitter: {gw_ping['jitter']} ms | Loss: {gw_ping['packetLoss']}%")
    
    print(f"[*] Probing Internet latency (8.8.8.8)...")
    net_ping = measure_ping_metrics("8.8.8.8", count=4)
    print(f"    -> Internet Latency: {net_ping['avgRtt']} ms | Jitter: {net_ping['jitter']} ms | Loss: {net_ping['packetLoss']}%")
    
    print(f"[*] Measuring DNS query latency...")
    dns_ok, dns_latency = measure_dns_latency()
    print(f"    -> DNS Response: {dns_latency} ms (Active: {dns_ok})")
    
    print(f"[*] Probing mission-critical servers...")
    servers = load_servers(gw_ip)
    server_results = probe_all_servers(servers)
    up_count = sum(1 for s in server_results if s.get("status") == "ONLINE")
    print(f"    -> Servers Online: {up_count}/{len(server_results)}")
    
    print(f"[*] Evaluating Network Intelligence & Gateway roaming...")
    gw_intel = track_gateway_identity(gw_ip, wifi["gatewayMac"], wifi["ssid"])
    print(f"    -> Gateway Classification: {gw_intel['classification']}")
    
    neighbors = get_neighbor_table()
    conflicts = verify_ip_conflicts(neighbors)
    if conflicts:
        print(f"    -> [!] IP CONFLICT DETECTED: {len(conflicts)} conflict(s) verified.")
        
    bandwidth = measure_this_pc_bandwidth(iface)
    print(f"[*] Host Bandwidth: Rx: {bandwidth['rxRateKbps']} KB/s | Tx: {bandwidth['txRateKbps']} KB/s")
    
    incidents = correlate_incidents(gw_ping["online"], dns_ok, server_results)
    if incidents:
        print(f"[*] Incidents Correlated: {len(incidents)}")
        for inc in incidents:
            print(f"    - [{inc['severity']}] {inc['title']}: {inc['rootCause']}")
            
    print(f"[*] Constructing Observed vs Inferred Topology Map...")
    topology_svg = build_network_topology_svg(this_ip, gw_ip, wifi["gatewayMac"], neighbors, server_results)
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_data = {
        "timestamp": timestamp,
        "wifi": wifi,
        "gatewayPing": gw_ping,
        "internetPing": net_ping,
        "dns": {"ok": dns_ok, "latencyMs": dns_latency},
        "dnsServers": dns_servers,
        "servers": server_results,
        "gatewayIntel": gw_intel,
        "conflicts": conflicts,
        "bandwidth": bandwidth,
        "incidents": incidents,
        "topologySvg": topology_svg
    }
    
    html_markup = generate_obsidian_report(report_data)
    file_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(REPORTS_DIR, f"Ambaan_Report_{file_ts}.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_markup)
        
    print(f"\n[+] Obsidian Glass Diagnostic Report generated successfully:")
    print(f"    {report_path}")
    
    # Try launching report in default browser if desktop session active
    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        try:
            subprocess.Popen(["xdg-open", report_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("[+] Opened diagnostic report in default web browser.")
        except Exception:
            pass
            
    print("=================================================================\n")

if __name__ == "__main__":
    main()
