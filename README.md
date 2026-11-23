# Ambaan Network Intelligence & Reliability Platform (v3.0)

A high-performance, local-first network monitoring, incident correlation, and infrastructure diagnostics platform engineered for Windows (10/11) and Linux (Ubuntu/Debian). Designed for systems engineers, network administrators, and technical operators requiring non-administrator privilege execution, offline execution, and zero telemetry.

---

## Table of Contents

- [Overview](#overview)
- [Multi-Platform Architecture](#multi-platform-architecture)
- [Repository Structure](#repository-structure)
- [Downloading and Extracting the Project](#downloading-and-extracting-the-project)
- [Running on Windows (Step-by-Step)](#running-on-windows-step-by-step)
- [Running on Ubuntu Linux (Step-by-Step)](#running-on-ubuntu-linux-step-by-step)
- [Core Subsystems](#core-subsystems)
  - [1. Real-Time Host Telemetry and 802.11 Metrics](#1-real-time-host-telemetry-and-80211-metrics)
  - [2. Remote Server and Service Probing](#2-remote-server-and-service-probing)
  - [3. Root-Cause Incident Correlation Engine](#3-root-cause-incident-correlation-engine)
  - [4. Topology Modeling and Relationship Taxonomy](#4-topology-modeling-and-relationship-taxonomy)
  - [5. Anomaly Detection and False-Positive Hardening](#5-anomaly-detection-and-false-positive-hardening)
  - [6. Quality of Service, Jitter, and SLA Tracking](#6-quality-of-service-jitter-and-sla-tracking)
  - [7. Self-Contained Offline HTML Dossier](#7-self-contained-offline-html-dossier)
- [Feature Comparison Matrix](#feature-comparison-matrix)
- [Security and Privacy Engineering](#security-and-privacy-engineering)
- [Configuration Reference](#configuration-reference)
- [Attribution and Provenance](#attribution-and-provenance)

---

## Overview

Ambaan began as an interactive desktop Wi-Fi notifier and has matured into an industrial-grade dual-platform Network Operations Center (NOC) and diagnostics suite.

The platform provides complete cross-platform parity across Windows and Ubuntu Linux:
- **Windows**: Built with native PowerShell 5.1 and .NET WinForms/WPF libraries. Requires no third-party package managers, runtimes, background services, or cloud connections.
- **Ubuntu Linux**: Built with native Python 3, Tkinter GUI, and Linux kernel networking (`iproute2`, `/proc/net`, `socket`). Functions without external pip dependencies and includes an automated interactive Terminal HUD fallback for headless servers or remote SSH sessions.

All telemetry—including ARP neighbor sweeps, route diagnostics, ICMP jitter calculations, synthetic server probes, and anomaly detection—is evaluated and stored locally in structured formats (CSV and JSON).

---

## Multi-Platform Architecture

```
+---------------------------------------------------------------------------------------+
|                                    INPUT TELEMETRY                                    |
|                                                                                       |
|   [Windows 10/11 Subsystem]                            [Ubuntu Linux Subsystem]       |
|    - netsh wlan / Get-NetAdapter                        - iproute2 / nmcli / procfs   |
|    - PowerShell 5.1 & .NET Runtime                      - Python 3 Kernel Sockets     |
|    - WinForms HUD & WPF Layering                        - Tkinter HUD & Terminal TUI  |
+------------------------------------------+--------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
|                             AMBAAN 3.0 INTELLIGENCE CORE                              |
|                                                                                       |
|   +------------------------------+             +----------------------------------+   |
|   | Incident Correlation Engine  |             | Topology Taxonomy Engine         |   |
|   | - Signal Synthesis           |             | - Confirmed Observed Links       |   |
|   | - Dependency Mapping         |             | - Inferred Layer-2 Paths         |   |
|   | - Alert Storm Suppression    |             | - Target Service Endpoints       |   |
|   +------------------------------+             +----------------------------------+   |
|   +------------------------------+             +----------------------------------+   |
|   | Anomaly Detection Engine     |             | SLA & Quality Analytics          |   |
|   | - Windowed IP Conflict Verification        | - RFC 3550 Latency Jitter        |   |
|   | - Gateway Roaming Classification           | - Rolling Availability Ratio     |   |
|   | - DNS Resolver Health Validation           | - Outage Duration Interval Logs  |   |
|   +------------------------------+             +----------------------------------+   |
+------------------------------------------+--------------------------------------------+
                                           |
                   +-----------------------+-----------------------+
                   |                                               |
                   v                                               v
+--------------------------------------+       +----------------------------------------+
|          DESKTOP HUD ENGINES         |       |         OFFLINE REPORTING DOSSIER      |
|                                      |       |                                        |
| - Windows: Obsidian WinForms Widget  |       | - Standalone HTML5/SVG Dashboard       |
| - Ubuntu: Tkinter Floating Widget    |       | - Pure Vector Topology Visualizer      |
| - Headless: Live Terminal TUI HUD    |       | - Zero External CDN Dependencies       |
| - Draggable, Frameless HUD Interface |       | - Air-Gapped Network Verification      |
+--------------------------------------+       +----------------------------------------+
```

---

## Repository Structure

The repository is organized into dedicated platform directories alongside shared configuration and asset specifications:

```
ambaan-wifi-guard/
|-- ATTRIBUTION.md               # Upstream provenance and author credits
|-- README.md                    # Platform documentation and operation guide
|-- .gitignore                   # Operational log exclusion filters
|
|-- windows/                     # Native Windows 10/11 Implementation
|   |-- Start-Floating-Widget.bat# Double-click launcher for Windows HUD
|   |-- Run-WiFi-Analyzer.bat    # Double-click launcher for diagnostic analyzer
|   |-- WiFi-Floating-Widget.ps1 # Primary Windows HUD script (PowerShell 5.1)
|   |-- WiFiNetworkAnalyzerPro.ps1# Comprehensive Windows network diagnostics
|   |-- ServerMonitor.ps1        # ICMP, TCP, HTTP synthetic probing engine
|   |-- NetworkIntelligence.ps1  # Incident correlation and anomaly detector
|   |-- TopologyEngine.ps1       # Topology graph modeler and vector generator
|   |-- NetSafety.ps1            # Safety checks and credential validation
|   |-- assets/                  # Shared audio, sprite, and animation assets
|   |-- MonitorData/             # Local database (servers.json, outages.json)
|   |-- Reports/                 # Generated offline HTML dossiers
|   `-- History/                 # Historical metric snapshots
|
`-- ubuntu/                      # Native Ubuntu Linux Implementation
    |-- setup.sh                 # Environment setup and dependency validation
    |-- start-floating-widget.sh # Launcher for Linux Tkinter / TUI HUD
    |-- run-wifi-analyzer.sh     # Launcher for Linux diagnostic analyzer
    |-- ambaan_widget.py         # Native Python 3 Tkinter floating desktop HUD
    |-- ambaan_analyzer.py       # Linux network diagnostic & report generator
    |-- server_monitor.py        # Linux ICMP, TCP, HTTP prober and SLA tracker
    |-- network_intelligence.py  # Gateway roaming, IP conflict, and incident engine
    |-- topology_engine.py       # SVG network topology generator with link taxonomy
    |-- assets/                  # Shared animation and audio resources
    |-- MonitorData/             # Local JSON storage and state tracking
    |-- Reports/                 # Generated offline HTML dossiers
    `-- History/                 # Historical telemetry records
```

---

## Downloading and Extracting the Project

You can obtain the project either by downloading the repository ZIP file from GitHub or by cloning the repository using Git.

### Option A: Download Repository ZIP (Recommended for most users)

1. Navigate to the repository page on GitHub.
2. Click the green **Code** button near the top right of the page.
3. Select **Download ZIP** from the dropdown menu.
4. Once downloaded, extract the archive:
   - **On Windows**: Right-click the downloaded `.zip` file, select **Extract All...**, choose a destination directory (for example, `C:\Tools\ambaan-wifi-guard`), and click **Extract**.
   - **On Ubuntu Linux**: Open your file manager, right-click the `.zip` file, and select **Extract Here**, or run the following in terminal:
     ```bash
     unzip ambaan-wifi-guard-main.zip -d ambaan-wifi-guard
     cd ambaan-wifi-guard
     ```

### Option B: Clone via Git

Open your terminal or command prompt and clone the repository:
```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>
```

After extraction, you will see two platform folders:
- `windows/`: Contains all files and launchers for Windows 10 and 11.
- `ubuntu/`: Contains all scripts and launchers for Ubuntu / Debian Linux.

---

## Running on Windows (Step-by-Step)

### System Requirements
- Windows 10 or Windows 11 (64-bit recommended)
- Windows PowerShell 5.1 (installed by default on Windows 10 and 11)
- Active Wi-Fi or Ethernet network connection
- Standard user permissions (No administrator privileges required)

### Step 1: Open the Windows Directory
Navigate to the extracted repository folder and open the `windows/` directory in File Explorer:
```
ambaan-wifi-guard/windows/
```

### Step 2: Unblock Downloaded Scripts (If prompted by Windows)
If Windows SmartScreen or file protection blocks downloaded scripts:
1. Right-click `WiFi-Floating-Widget.ps1`, select **Properties**, check the **Unblock** box at the bottom, and click **OK**.
2. Repeat for `WiFiNetworkAnalyzerPro.ps1` if needed.
Alternatively, running through the included `.bat` files bypasses execution policy restrictions automatically.

### Step 3: Launching the Applications

#### Method 1: One-Click Launchers (Graphical)
- **To launch the Desktop Floating Widget**:
  Double-click `Start-Floating-Widget.bat`.
  The dark Obsidian Glass HUD will appear at the top-right corner of your desktop, showing real-time Wi-Fi signal percentage, link speed, latency, host bandwidth, and server status. You can click and drag the widget anywhere on your screen.
- **To run the Full Network Diagnostic Analyzer**:
  Double-click `Run-WiFi-Analyzer.bat`.
  A terminal window will open, perform automated latency, jitter, DNS, and server probes, build the network topology map, and automatically open an interactive offline HTML report in your default web browser.

#### Method 2: PowerShell Terminal
If you prefer running from PowerShell directly:
```powershell
cd windows

# Launch the floating desktop widget:
powershell -ExecutionPolicy Bypass -File .\WiFi-Floating-Widget.ps1

# Run the comprehensive diagnostic analyzer:
powershell -ExecutionPolicy Bypass -File .\WiFiNetworkAnalyzerPro.ps1
```

### Troubleshooting on Windows
- If PowerShell reports that script execution is disabled on your machine, running with the `-ExecutionPolicy Bypass` flag as shown above allows the script to run safely for that session without modifying system-wide security policies.

---

## Running on Ubuntu Linux (Step-by-Step)

### System Requirements
- Ubuntu 20.04 LTS, 22.04 LTS, 24.04 LTS, or Debian-based distributions
- Python 3.8 or newer (pre-installed on all modern Ubuntu systems)
- Standard network utilities: `iproute2`, `iputils-ping`
- For graphical desktop widget: `python3-tk` (optional; falls back to real-time Terminal HUD if absent)

### Step 1: Open Terminal and Navigate to the Ubuntu Directory
Open your terminal and change directory into the `ubuntu/` folder:
```bash
cd ambaan-wifi-guard/ubuntu
```

### Step 2: Grant Execution Permissions and Run Setup
Run the environment setup script to ensure executable permissions and verify system packages:
```bash
chmod +x *.sh *.py
./setup.sh
```

If any recommended system utilities are missing, install them with:
```bash
sudo apt update
sudo apt install -y python3 python3-tk iproute2 iputils-ping
```

### Step 3: Launching the Applications

#### A. Running the Desktop Floating Widget
To launch the real-time floating HUD:
```bash
./start-floating-widget.sh
```
- **On a Graphical Desktop (GNOME / X11 / Wayland)**:
  A frameless Obsidian Glass widget appears on your screen showing the animated Dhamu character, active Wi-Fi signal, link rate, ping, jitter, host bandwidth, and server availability. You can click and drag the widget anywhere on your desktop.
- **On Headless Servers or Remote SSH Sessions**:
  If no graphical display is detected, Ambaan automatically switches to an in-place **Terminal TUI HUD** that continuously updates network telemetry directly in your console. Press `Ctrl+C` at any time to exit.

#### B. Running the Comprehensive Diagnostic Analyzer
To execute a complete network health check:
```bash
./run-wifi-analyzer.sh
```
What happens during execution:
1. Detects primary network interface, active IP, default gateway, and Wi-Fi signal metrics.
2. Measures gateway and internet round-trip time, packet loss, and RFC 3550 jitter.
3. Probes mission-critical servers (ICMP, TCP ports, HTTP/HTTPS endpoints) and evaluates SLA ratios.
4. Identifies potential ARP spoofing vs. mesh Wi-Fi roaming, and checks for IP conflicts.
5. Measures host bandwidth throughput from `/proc/net/dev`.
6. Generates a standalone, air-gapped HTML dossier in `Reports/` with an interactive vector topology map.
7. Automatically opens the report in your default browser (using `xdg-open`).

### Troubleshooting on Ubuntu
- If `./start-floating-widget.sh` reports that Tkinter is not installed and you want the graphical floating window, run `sudo apt install -y python3-tk`. If you are over SSH, the Terminal HUD will run automatically without needing Tkinter.

---

## Core Subsystems

### 1. Real-Time Host Telemetry and 802.11 Metrics
- **Radio Parameters**: Signal strength percentage, operating channel, frequency band (2.4 GHz vs. 5 GHz), and theoretical PHY link rate.
- **Host Traffic Metering**: Measures instantaneous transmit and receive bandwidth specifically on the active host interface.
- **Scope Isolation**: Explicitly marks host interface statistics as "This PC Only" to prevent misrepresenting overall router or local subnet bandwidth.

### 2. Remote Server and Service Probing
- **ICMP Ping**: Multiple consecutive echo requests to determine minimum, average, and maximum round-trip times along with packet loss.
- **TCP Socket Handshakes**: Direct socket connections against target TCP ports (e.g., DNS port 53, SSH port 22, HTTP port 80, HTTPS port 443, database ports).
- **HTTP/HTTPS Endpoint Checks**: Synthetic GET/POST queries verifying HTTP status codes and response timeliness.

### 3. Root-Cause Incident Correlation Engine
Suppresses cascading alerts during upstream failures. For example:
- If the default gateway is unresponsive, all dependent internet and server alerts are consolidated into a single "Local Gateway Outage" incident.
- If the gateway is reachable but external DNS and servers are down, the issue is classified as an "Upstream WAN / ISP Outage".

### 4. Topology Modeling and Relationship Taxonomy
To maintain strict engineering accuracy, the visualizer distinguishes verified physical relationships from inferred logical paths:
- **Solid Stroke**: Direct, observed host neighbor link verified via active ARP / neighbor cache.
- **Dashed Stroke**: Inferred Layer-2 or Layer-3 relationship (such as unverified switch hops, router-to-device links, or WAN uplinks).

### 5. Anomaly Detection and False-Positive Hardening
- **Gateway Identity Drift**: Tracks gateway MAC address changes over time. Differentiates normal Wi-Fi mesh roaming (matching vendor OUI) from suspicious ARP changes.
- **Windowed IP Conflict Verification**: Requires repeated conflicting observations across a minimum time threshold before escalating an alert, preventing false positives caused by transient ARP cache entries or rapid DHCP leasing.
- **DNS Shield**: Validates the responsiveness and integrity of configured DNS resolvers.

### 6. Quality of Service, Jitter, and SLA Tracking
- **RFC 3550 Jitter**: Implements the standard RTP statistical variance calculation to track packet arrival variation.
- **Observed SLA Percentage**: Calculates continuous uptime ratios for all monitored infrastructure targets.
- **Outage Interval Records**: Records start time, recovery time, and total downtime duration for each target.

### 7. Self-Contained Offline HTML Dossier
- Generates a standalone, air-gapped HTML diagnostic dossier in `Reports/`.
- Embedded SVG network topology diagram with interactive node inspection.
- Pure inline CSS and SVG—100% functional without internet connectivity or external CDN access.

---

## Feature Comparison Matrix

| Capability | Initial Baseline (v1.0) | Ambaan 3.0 Platform (v3.0) |
| :--- | :--- | :--- |
| **Operating System Support** | Windows Only | Dual Platform: Windows 10/11 & Ubuntu Linux |
| **Server and Endpoint Probing** | None | Multi-protocol (ICMP, TCP Handshake, HTTP/HTTPS) |
| **Incident Management** | Isolated popups | Root-cause incident correlation engine |
| **Topology Representation** | None | Interactive SVG with Observed vs. Inferred taxonomy |
| **Jitter Calculation** | None | RFC 3550 statistical variance metric |
| **SLA Tracking** | None | Rolling observed availability and downtime log |
| **Bandwidth Intelligence** | Raw adapter bytes | Host-scoped rate calculation with strict labeling |
| **Gateway Roaming Analysis** | Unchecked MAC alerts | Mesh roaming vs. ARP spoofing classification |
| **IP Conflict Detection** | Immediate naive match | Windowed multi-cycle verification |
| **UI Theme** | Legacy Purple | Obsidian Glass design system with 1px borders |
| **Report Dependencies** | External CDN links | Zero external CDNs (100% offline air-gapped) |
| **Headless Execution** | Unsupported | Automated Terminal TUI HUD fallback |

---

## Security and Privacy Engineering

1. **Non-Administrator Execution**: Operates within standard user privileges. No kernel drivers or administrative elevation required.
2. **Local Data Persistence**: All logs, server inventories, and reports are saved strictly inside the application root directory (`MonitorData/`, `Reports/`, `History/`).
3. **No External Telemetry**: Zero outbound phone-home calls, analytics pings, or third-party dependencies.
4. **Input Sanitization**: Hostnames, SSIDs, and server descriptions are escaped prior to HTML rendering to eliminate cross-site scripting risks.
5. **Air-Gapped Operation**: Reports and dashboards function without internet connectivity.

---

## Configuration Reference

The target server configuration file is stored locally in `MonitorData/servers.json`:

```json
[
  {
    "id": "srv-gw",
    "name": "Default Gateway",
    "host": "192.168.1.1",
    "type": "GATEWAY",
    "checkType": "PING",
    "expectedCode": 200,
    "timeoutMs": 1500,
    "slaTarget": 99.9
  },
  {
    "id": "srv-dns-google",
    "name": "Primary DNS",
    "host": "8.8.8.8",
    "port": 53,
    "type": "DNS",
    "checkType": "TCP",
    "expectedCode": 200,
    "timeoutMs": 1000,
    "slaTarget": 99.5
  },
  {
    "id": "srv-web",
    "name": "Web Infrastructure",
    "host": "https://cloudflare.com",
    "type": "HTTP",
    "checkType": "HTTPS",
    "expectedCode": 200,
    "timeoutMs": 2000,
    "slaTarget": 99.0
  }
]
```

Fields:
- `id`: Unique identifier for the server entry.
- `name`: Human-readable label displayed in widgets and reports.
- `host`: IP address, domain name, or full HTTP/HTTPS URL.
- `port`: TCP target port (used when `checkType` is `TCP`).
- `checkType`: Probe protocol: `PING`, `TCP`, `HTTP`, or `HTTPS`.
- `expectedCode`: Expected HTTP response status code (e.g., `200`, `301`).
- `timeoutMs`: Probe timeout in milliseconds.
- `slaTarget`: Target operational percentage (e.g., `99.9`).

---

## Attribution and Provenance

- **Original Concept and Core Assets**: ShiftLogic Labs  
  Original documentation and foundational media assets: [ShiftLogic Labs Ambaan Wi-Fi Guard](https://shiftlogiclabs.in/docs/ambaan-wifi-guard).
- **Platform Architecture and v3.0 Expansion**: Vaisakh Sriram  
  Architecture, network intelligence engine, multi-protocol server monitoring, topology modeler, incident correlation, Obsidian Glass interface redesign, and native Ubuntu Linux suite.

Detailed license and component provenance information is maintained in [ATTRIBUTION.md](ATTRIBUTION.md).
