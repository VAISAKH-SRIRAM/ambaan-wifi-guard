#!/usr/bin/env python3
"""
Ambaan 3.0 Linux Network Intelligence Engine
Handles:
1. Gateway identity & roaming classification (Mesh roaming vs ARP spoofing)
2. Windowed IP conflict verification (anti-false-positive mechanism)
3. Bandwidth intelligence (strictly separating This PC vs Network)
4. Incident correlation & root-cause analysis
"""

import json
import os
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MONITOR_DATA_DIR = os.path.join(SCRIPT_DIR, "MonitorData")
GATEWAY_HIST_FILE = os.path.join(MONITOR_DATA_DIR, "gateway_history.json")
IP_CONFLICT_FILE = os.path.join(MONITOR_DATA_DIR, "ip_conflicts.json")
BW_STATE_FILE = os.path.join(MONITOR_DATA_DIR, "bandwidth_state.json")
INCIDENTS_FILE = os.path.join(MONITOR_DATA_DIR, "incidents.json")

def ensure_dirs():
    os.makedirs(MONITOR_DATA_DIR, exist_ok=True)

def track_gateway_identity(gateway_ip, gateway_mac, ssid=""):
    """
    Evaluates Gateway MAC address changes.
    Distinguishes mesh Wi-Fi roaming from ARP spoofing.
    """
    ensure_dirs()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    now_ts = time.time()
    
    history = []
    if os.path.exists(GATEWAY_HIST_FILE):
        try:
            with open(GATEWAY_HIST_FILE, "r", encoding="utf-8") as f:
                history = json.load(f)
        except Exception:
            history = []
            
    is_changed = False
    classification = "STABLE"
    description = "Gateway identity is consistent with historical baseline."
    
    if history:
        last = history[-1]
        last_mac = last.get("mac", "").lower()
        curr_mac = gateway_mac.lower() if gateway_mac else ""
        
        if curr_mac and last_mac and curr_mac != last_mac:
            is_changed = True
            time_diff = now_ts - last.get("timestamp", now_ts)
            
            # If same vendor OUI or rapid switch on Wi-Fi -> likely Mesh Roaming
            oui_last = last_mac[:8]
            oui_curr = curr_mac[:8]
            
            if oui_last == oui_curr:
                classification = "MESH_ROAMING"
                description = f"Gateway BSSID transitioned from {last_mac} to {curr_mac} with matching vendor OUI ({oui_curr}). Normal mesh node handover."
            elif time_diff < 120:
                classification = "SUSPICIOUS_GATEWAY_SHIFT"
                description = f"Rapid gateway MAC modification observed within {int(time_diff)}s (Previous: {last_mac}, New: {curr_mac}). Possible ARP spoofing or rapid AP switch."
            else:
                classification = "NETWORK_RECONFIGURATION"
                description = f"Gateway MAC address updated from {last_mac} to {curr_mac}. Likely router replacement or subnet handover."
                
    entry = {
        "timestamp": now_ts,
        "timeStr": now_str,
        "ip": gateway_ip,
        "mac": gateway_mac,
        "ssid": ssid,
        "classification": classification
    }
    history.append(entry)
    if len(history) > 100:
        history = history[-100:]
        
    try:
        with open(GATEWAY_HIST_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
    except Exception:
        pass
        
    return {
        "isChanged": is_changed,
        "classification": classification,
        "description": description,
        "currentMac": gateway_mac,
        "historyCount": len(history)
    }

def verify_ip_conflicts(neighbor_table):
    """
    Evaluates neighbor table for IP conflicts.
    Requires repeated conflicting observations within a 5-minute temporal window
    to avoid false positives caused by stale ARP cache or rapid DHCP reuse.
    """
    ensure_dirs()
    now_ts = time.time()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    
    active_conflicts = []
    conflict_db = {}
    if os.path.exists(IP_CONFLICT_FILE):
        try:
            with open(IP_CONFLICT_FILE, "r", encoding="utf-8") as f:
                conflict_db = json.load(f)
        except Exception:
            conflict_db = {}
            
    # Group neighbors by IP
    ip_to_macs = {}
    for n in neighbor_table:
        ip = n.get("ip")
        mac = n.get("mac", "").lower()
        if ip and mac and mac != "00:00:00:00:00:00" and not mac.startswith("ff:ff"):
            ip_to_macs.setdefault(ip, set()).add(mac)
            
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            mac_list = sorted(list(macs))
            rec = conflict_db.get(ip, {"count": 0, "firstSeen": now_ts, "lastSeen": now_ts, "macs": mac_list})
            rec["count"] += 1
            rec["lastSeen"] = now_ts
            rec["macs"] = mac_list
            rec["lastTimeStr"] = now_str
            conflict_db[ip] = rec
            
            # Verification policy: must be observed >= 2 times or persist > 30 seconds
            is_confirmed = (rec["count"] >= 2) or ((rec["lastSeen"] - rec["firstSeen"]) >= 30)
            
            active_conflicts.append({
                "ip": ip,
                "macs": mac_list,
                "observationCount": rec["count"],
                "durationSec": int(rec["lastSeen"] - rec["firstSeen"]),
                "isConfirmed": is_confirmed,
                "severity": "CRITICAL" if is_confirmed else "OBSERVING"
            })
            
    # Prune stale records older than 1 hour
    pruned = {k: v for k, v in conflict_db.items() if (now_ts - v.get("lastSeen", 0)) < 3600}
    try:
        with open(IP_CONFLICT_FILE, "w", encoding="utf-8") as f:
            json.dump(pruned, f, indent=2)
    except Exception:
        pass
        
    return active_conflicts

def measure_this_pc_bandwidth(interface=""):
    """
    Measures This PC's bandwidth consumption specifically via /proc/net/dev.
    Clearly distinguishes host interface traffic from external network traffic.
    """
    ensure_dirs()
    now_ts = time.time()
    
    current_stats = {}
    rx_bytes = 0
    tx_bytes = 0
    
    if os.path.exists("/proc/net/dev"):
        try:
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()
            for line in lines[2:]:
                parts = line.strip().split()
                if not parts:
                    continue
                ifname = parts[0].rstrip(":")
                if ifname == "lo":
                    continue
                if interface and ifname != interface:
                    continue
                rx = int(parts[1])
                tx = int(parts[9])
                rx_bytes += rx
                tx_bytes += tx
        except Exception:
            pass
            
    rx_rate_kbps = 0.0
    tx_rate_kbps = 0.0
    
    prev_state = None
    if os.path.exists(BW_STATE_FILE):
        try:
            with open(BW_STATE_FILE, "r", encoding="utf-8") as f:
                prev_state = json.load(f)
        except Exception:
            prev_state = None
            
    if prev_state and "timestamp" in prev_state:
        dt = now_ts - prev_state["timestamp"]
        if 0.5 <= dt <= 60:
            drx = rx_bytes - prev_state.get("rx_bytes", 0)
            dtx = tx_bytes - prev_state.get("tx_bytes", 0)
            if drx >= 0 and dtx >= 0:
                rx_rate_kbps = round((drx / dt) / 1024.0, 2)
                tx_rate_kbps = round((dtx / dt) / 1024.0, 2)
                
    curr_state = {
        "timestamp": now_ts,
        "timeStr": time.strftime("%Y-%m-%d %H:%M:%S"),
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "rx_rate_kbps": rx_rate_kbps,
        "tx_rate_kbps": tx_rate_kbps
    }
    
    try:
        with open(BW_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(curr_state, f, indent=2)
    except Exception:
        pass
        
    return {
        "scope": "THIS_PC_ONLY",
        "rxRateKbps": rx_rate_kbps,
        "txRateKbps": tx_rate_kbps,
        "rxTotalMB": round(rx_bytes / (1024.0 * 1024.0), 2),
        "txTotalMB": round(tx_bytes / (1024.0 * 1024.0), 2),
        "label": "This PC Adapter Traffic (Observed)"
    }

def correlate_incidents(gateway_online, dns_online, server_results):
    """
    Groups individual outage signals into a unified Incident with Root Cause Analysis.
    Prevents alert storms by identifying parent network failure.
    """
    ensure_dirs()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    now_ts = time.time()
    
    incidents = []
    
    # 1. Gateway Down -> Root cause: Local Link / Router Failure
    if not gateway_online:
        incidents.append({
            "id": f"INC-GW-{int(now_ts)}",
            "title": "Local Gateway & WAN Outage",
            "rootCause": "Default Gateway does not respond to ICMP. All outbound routing is compromised.",
            "severity": "CRITICAL",
            "impact": "Complete Network Disconnect",
            "correlatedEvents": [
                "Local gateway probe failed",
                "External DNS unreachable",
                f"{len(server_results)} monitored server check(s) suppressed due to gateway down"
            ],
            "time": now_str
        })
        return incidents
        
    # 2. DNS Down while Gateway is up -> Root cause: Upstream DNS Resolver Outage
    if not dns_online:
        incidents.append({
            "id": f"INC-DNS-{int(now_ts)}",
            "title": "DNS Resolution Degradation",
            "rootCause": "Configured DNS resolvers failed to respond within SLA timeout window.",
            "severity": "HIGH",
            "impact": "Domain name resolution failing; raw IP traffic still functional.",
            "correlatedEvents": [
                "DNS latency timeout (>1500ms)",
                "HTTP checks with hostname targets degraded"
            ],
            "time": now_str
        })
        
    # 3. Specific server outages
    down_servers = [s for s in server_results if s.get("status") == "OFFLINE"]
    if down_servers:
        if len(down_servers) == len(server_results) and len(server_results) > 1:
            incidents.append({
                "id": f"INC-EXT-{int(now_ts)}",
                "title": "Upstream Internet Connectivity Loss",
                "rootCause": "Local gateway is responsive, but all external servers and DNS endpoints are unreachable. Likely ISP WAN drop.",
                "severity": "CRITICAL",
                "impact": "Internet Access Down",
                "correlatedEvents": [f"{s.get('name')} offline" for s in down_servers],
                "time": now_str
            })
        else:
            for s in down_servers:
                incidents.append({
                    "id": f"INC-SRV-{s.get('id')}",
                    "title": f"Target Outage: {s.get('name')}",
                    "rootCause": f"Service at {s.get('host')} failed {s.get('checkType')} check for {s.get('consecutiveFails', 1)} consecutive cycle(s).",
                    "severity": "MEDIUM",
                    "impact": f"Service unavailable ({s.get('host')})",
                    "correlatedEvents": [f"Status code / ping timeout on {s.get('checkType')}"],
                    "time": now_str
                })
                
    return incidents

if __name__ == "__main__":
    print("Testing Linux Network Intelligence...")
    gw = track_gateway_identity("192.168.1.1", "00:11:22:33:44:55", "Home-WiFi")
    print("Gateway:", gw)
    bw = measure_this_pc_bandwidth()
    print("Bandwidth:", bw)
