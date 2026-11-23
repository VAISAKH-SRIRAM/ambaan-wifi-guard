#!/usr/bin/env python3
"""
Ambaan 3.0 Linux Server Monitor
Monitors ICMP ping, TCP port availability, and HTTP/HTTPS endpoints with SLA tracking,
RFC 3550 jitter calculation, and zero external dependencies.
"""

import json
import os
import re
import socket
import subprocess
import time
import urllib.request
import urllib.error

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MONITOR_DATA_DIR = os.path.join(SCRIPT_DIR, "MonitorData")
SERVERS_FILE = os.path.join(MONITOR_DATA_DIR, "servers.json")
OUTAGES_FILE = os.path.join(MONITOR_DATA_DIR, "outages.json")

DEFAULT_SERVERS = [
    {
        "id": "srv-gw",
        "name": "Default Gateway",
        "host": "192.168.1.1",
        "type": "GATEWAY",
        "checkType": "PING",
        "expectedCode": 200,
        "timeoutMs": 1500,
        "slaTarget": 99.9,
        "totalChecks": 0,
        "successChecks": 0,
        "consecutiveFails": 0
    },
    {
        "id": "srv-dns-google",
        "name": "Primary DNS (Google)",
        "host": "8.8.8.8",
        "port": 53,
        "type": "DNS",
        "checkType": "TCP",
        "expectedCode": 200,
        "timeoutMs": 1000,
        "slaTarget": 99.5,
        "totalChecks": 0,
        "successChecks": 0,
        "consecutiveFails": 0
    },
    {
        "id": "srv-cf-dns",
        "name": "Cloudflare DNS",
        "host": "1.1.1.1",
        "port": 53,
        "type": "DNS",
        "checkType": "TCP",
        "expectedCode": 200,
        "timeoutMs": 1000,
        "slaTarget": 99.9,
        "totalChecks": 0,
        "successChecks": 0,
        "consecutiveFails": 0
    }
]

def ensure_dirs():
    os.makedirs(MONITOR_DATA_DIR, exist_ok=True)

def load_servers(gateway_ip=None):
    ensure_dirs()
    if not os.path.exists(SERVERS_FILE):
        servers = DEFAULT_SERVERS
        if gateway_ip and gateway_ip != "0.0.0.0":
            servers[0]["host"] = gateway_ip
        save_servers(servers)
        return servers
    try:
        with open(SERVERS_FILE, "r", encoding="utf-8") as f:
            servers = json.load(f)
            if gateway_ip and gateway_ip != "0.0.0.0":
                for s in servers:
                    if s.get("type") == "GATEWAY":
                        s["host"] = gateway_ip
            return servers
    except Exception:
        return DEFAULT_SERVERS

def save_servers(servers):
    ensure_dirs()
    with open(SERVERS_FILE, "w", encoding="utf-8") as f:
        json.dump(servers, f, indent=2)

def ping_host(host, timeout_sec=1):
    """Executes a system ping and returns (is_up, rtt_ms, jitter_ms)"""
    try:
        cmd = ["ping", "-c", "3", "-W", str(max(1, int(timeout_sec))), host]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout_sec * 4)
        if proc.returncode != 0:
            return False, None, 0.0
        
        # Parse ping times: 64 bytes from ...: icmp_seq=1 ttl=64 time=1.23 ms
        times = [float(m) for m in re.findall(r"time=([\d\.]+)\s*ms", proc.stdout)]
        if not times:
            return True, 1.0, 0.0
        
        avg_rtt = sum(times) / len(times)
        
        # Calculate RFC 3550 Jitter
        jitter = 0.0
        for i in range(1, len(times)):
            d = abs(times[i] - times[i-1])
            jitter += (d - jitter) / 16.0
            
        return True, round(avg_rtt, 2), round(jitter, 2)
    except Exception:
        return False, None, 0.0

def check_tcp_port(host, port, timeout_sec=1.5):
    """Probes a TCP port via socket connection."""
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_sec)
    try:
        s.connect((host, int(port)))
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        s.close()
        return True, round(elapsed_ms, 2)
    except Exception:
        return False, None

def check_http_endpoint(url, expected_code=200, timeout_sec=2.0):
    """Checks an HTTP or HTTPS endpoint."""
    t0 = time.perf_counter()
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Ambaan-WiFi-Guard/3.0 (Ubuntu-Linux)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            code = resp.getcode()
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            is_valid = (code == expected_code) or (expected_code == 200 and 200 <= code < 400)
            return is_valid, round(elapsed_ms, 2), code
    except urllib.error.HTTPError as e:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        is_valid = (e.code == expected_code)
        return is_valid, round(elapsed_ms, 2), e.code
    except Exception:
        return False, None, 0

def probe_all_servers(servers):
    """Probes all configured servers and records SLA / outage state."""
    results = []
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    
    for s in servers:
        s_id = s.get("id", "srv-" + str(int(time.time())))
        name = s.get("name", "Unknown Server")
        host = s.get("host", "127.0.0.1")
        check_type = s.get("checkType", "PING").upper()
        expected = s.get("expectedCode", 200)
        timeout_sec = s.get("timeoutMs", 1500) / 1000.0
        
        is_up = False
        rtt_ms = None
        jitter_ms = 0.0
        http_code = None
        
        if check_type == "PING":
            is_up, rtt_ms, jitter_ms = ping_host(host, timeout_sec)
        elif check_type == "TCP":
            port = s.get("port", 80)
            is_up, rtt_ms = check_tcp_port(host, port, timeout_sec)
        elif check_type in ("HTTP", "HTTPS"):
            url = host if host.startswith("http") else f"{check_type.lower()}://{host}"
            is_up, rtt_ms, http_code = check_http_endpoint(url, expected, timeout_sec)
            
        total = s.get("totalChecks", 0) + 1
        success = s.get("successChecks", 0) + (1 if is_up else 0)
        sla_pct = round((success / total) * 100.0, 2)
        consec_fails = 0 if is_up else (s.get("consecutiveFails", 0) + 1)
        
        s["totalChecks"] = total
        s["successChecks"] = success
        s["consecutiveFails"] = consec_fails
        s["observedSla"] = sla_pct
        s["lastCheck"] = now_str
        s["lastRtt"] = rtt_ms
        s["status"] = "ONLINE" if is_up else "OFFLINE"
        
        results.append({
            "id": s_id,
            "name": name,
            "host": host,
            "type": s.get("type", "SERVER"),
            "checkType": check_type,
            "status": "ONLINE" if is_up else "OFFLINE",
            "latencyMs": rtt_ms if rtt_ms is not None else -1,
            "jitterMs": jitter_ms,
            "slaTarget": s.get("slaTarget", 99.5),
            "observedSla": sla_pct,
            "consecutiveFails": consec_fails,
            "lastCheck": now_str,
            "httpCode": http_code
        })
        
    save_servers(servers)
    return results

if __name__ == "__main__":
    print("Testing Linux Server Monitor...")
    srvs = load_servers("127.0.0.1")
    res = probe_all_servers(srvs)
    print(json.dumps(res, indent=2))
