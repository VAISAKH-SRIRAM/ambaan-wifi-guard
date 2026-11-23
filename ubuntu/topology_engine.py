#!/usr/bin/env python3
"""
Ambaan 3.0 Linux Topology Engine
Generates interactive, accessible SVG network topology with strict link taxonomy:
- Solid Line: Confirmed Observed Link (direct ARP / IP neighbor observation)
- Dashed Line: Inferred L2/L3 Relationship (unverified physical path / WAN path)
"""

import html

def build_network_topology_svg(this_pc_ip, gateway_ip, gateway_mac, neighbors, servers):
    """
    Constructs an interactive SVG topology diagram.
    """
    width = 960
    height = 540
    
    # Coordinates
    wan_x, wan_y = 120, 270
    gw_x, gw_y = 340, 270
    pc_x, pc_y = 600, 160
    srv_center_x, srv_y = 800, 160
    dev_center_x, dev_y = 600, 390
    
    svg = []
    svg.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" class="w-full h-auto select-none" style="background:#090d16; border-radius:12px; font-family:ui-sans-serif, system-ui, sans-serif;">')
    
    # SVG Definitions (Gradients, filters)
    svg.append('''
    <defs>
      <linearGradient id="wanGrad" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="#0284c7" />
        <stop offset="100%" stop-color="#0369a1" />
      </linearGradient>
      <linearGradient id="gwGrad" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="#4f46e5" />
        <stop offset="100%" stop-color="#3730a3" />
      </linearGradient>
      <linearGradient id="pcGrad" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="#059669" />
        <stop offset="100%" stop-color="#047857" />
      </linearGradient>
      <linearGradient id="devGrad" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="#334155" />
        <stop offset="100%" stop-color="#1e293b" />
      </linearGradient>
      <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
        <feGaussianBlur stdDeviation="3" result="blur" />
        <feComposite in="SourceGraphic" in2="blur" operator="over" />
      </filter>
    </defs>
    ''')
    
    # Background Grid pattern
    svg.append('<g opacity="0.08">')
    for x in range(0, width, 40):
        svg.append(f'<line x1="{x}" y1="0" x2="{x}" y2="{height}" stroke="#94a3b8" stroke-width="1" />')
    for y in range(0, height, 40):
        svg.append(f'<line x1="0" y1="{y}" x2="{width}" y2="{y}" stroke="#94a3b8" stroke-width="1" />')
    svg.append('</g>')
    
    # Legend
    svg.append('''
    <g transform="translate(30, 30)">
      <rect width="320" height="75" rx="8" fill="#111827" stroke="#1f2937" stroke-width="1" />
      <text x="15" y="22" fill="#9ca3af" font-size="11" font-weight="700" letter-spacing="1">LINK RELATIONSHIP TAXONOMY</text>
      <!-- Solid -->
      <line x1="15" y1="42" x2="55" y2="42" stroke="#10b981" stroke-width="2.5" />
      <text x="65" y="46" fill="#e5e7eb" font-size="11">Solid: Observed Link (ARP / Host Neighbor)</text>
      <!-- Dashed -->
      <line x1="15" y1="62" x2="55" y2="62" stroke="#64748b" stroke-width="2" stroke-dasharray="5,4" />
      <text x="65" y="65" fill="#94a3b8" font-size="11">Dashed: Inferred Path (L2/L3 / WAN Uplink)</text>
    </g>
    ''')
    
    # Links
    # 1. WAN -> Gateway (Inferred uplink)
    svg.append(f'<line x1="{wan_x}" y1="{wan_y}" x2="{gw_x}" y2="{gw_y}" stroke="#38bdf8" stroke-width="2" stroke-dasharray="6,4" opacity="0.8" />')
    svg.append(f'<text x="{(wan_x+gw_x)//2}" y="{wan_y-12}" fill="#64748b" font-size="10" text-anchor="middle">ISP Uplink (Inferred)</text>')
    
    # 2. Gateway -> This PC (Observed host link)
    svg.append(f'<line x1="{gw_x}" y1="{gw_y}" x2="{pc_x}" y2="{pc_y}" stroke="#10b981" stroke-width="2.5" />')
    svg.append(f'<text x="{(gw_x+pc_x)//2 - 10}" y="{(gw_y+pc_y)//2 - 10}" fill="#10b981" font-size="10" font-weight="600" text-anchor="middle">Observed Active Link</text>')
    
    # 3. This PC -> Monitored Servers
    srv_list = servers[:4]
    if srv_list:
        for idx, srv in enumerate(srv_list):
            sy = 90 + idx * 75
            status_color = "#10b981" if srv.get("status") == "ONLINE" else "#ef4444"
            svg.append(f'<line x1="{pc_x}" y1="{pc_y}" x2="{srv_center_x}" y2="{sy}" stroke="{status_color}" stroke-width="1.8" stroke-dasharray="4,3" opacity="0.7" />')
            
            # Server node
            svg.append(f'''
            <g transform="translate({srv_center_x}, {sy})">
              <circle r="22" fill="#1e1e2e" stroke="{status_color}" stroke-width="2" filter="url(#glow)" />
              <text y="4" text-anchor="middle" fill="#f8fafc" font-size="10" font-weight="700">SRV</text>
              <text x="32" y="-2" fill="#f8fafc" font-size="11" font-weight="600">{html.escape(srv.get('name', 'Server')[:18])}</text>
              <text x="32" y="13" fill="#94a3b8" font-size="9">{html.escape(srv.get('host', ''))} • {srv.get('checkType')}</text>
              <text x="32" y="25" fill="{status_color}" font-size="9" font-weight="600">{srv.get('status')} • SLA {srv.get('observedSla', 100)}%</text>
            </g>
            ''')
            
    # 4. Gateway -> Other Local Devices (Inferred L2 paths from ARP table)
    dev_list = [n for n in neighbors if n.get("ip") != gateway_ip and n.get("ip") != this_pc_ip][:5]
    if dev_list:
        dev_start_x = 480
        for idx, dev in enumerate(dev_list):
            dx = dev_start_x + idx * 85
            dy = dev_y
            svg.append(f'<line x1="{gw_x}" y1="{gw_y}" x2="{dx}" y2="{dy}" stroke="#475569" stroke-width="1.5" stroke-dasharray="4,4" opacity="0.6" />')
            
            # Device node
            dev_ip = dev.get("ip", "")
            dev_mac = dev.get("mac", "")
            svg.append(f'''
            <g transform="translate({dx}, {dy})">
              <circle r="18" fill="url(#devGrad)" stroke="#64748b" stroke-width="1.5" />
              <text y="4" text-anchor="middle" fill="#94a3b8" font-size="9" font-weight="600">DEV</text>
              <text y="30" text-anchor="middle" fill="#cbd5e1" font-size="9" font-weight="500">{html.escape(dev_ip.split('.')[-1] if dev_ip else '')}</text>
              <text y="42" text-anchor="middle" fill="#64748b" font-size="7">{html.escape(dev_mac[-8:] if dev_mac else '')}</text>
            </g>
            ''')
            
    # Draw WAN Node
    svg.append(f'''
    <g transform="translate({wan_x}, {wan_y})">
      <circle r="36" fill="url(#wanGrad)" stroke="#38bdf8" stroke-width="2.5" filter="url(#glow)" />
      <text y="-5" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="700">WAN</text>
      <text y="12" text-anchor="middle" fill="#bae6fd" font-size="9">Internet</text>
    </g>
    ''')
    
    # Draw Gateway Node
    svg.append(f'''
    <g transform="translate({gw_x}, {gw_y})">
      <circle r="40" fill="url(#gwGrad)" stroke="#818cf8" stroke-width="2.5" filter="url(#glow)" />
      <text y="-8" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="700">ROUTER</text>
      <text y="7" text-anchor="middle" fill="#c7d2fe" font-size="9">{html.escape(gateway_ip or 'Gateway')}</text>
      <text y="20" text-anchor="middle" fill="#818cf8" font-size="8">{html.escape(gateway_mac[:14] if gateway_mac else '')}</text>
    </g>
    ''')
    
    # Draw This PC Node
    svg.append(f'''
    <g transform="translate({pc_x}, {pc_y})">
      <circle r="36" fill="url(#pcGrad)" stroke="#34d399" stroke-width="2.5" filter="url(#glow)" />
      <text y="-6" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="700">THIS PC</text>
      <text y="9" text-anchor="middle" fill="#a7f3d0" font-size="9">{html.escape(this_pc_ip or 'Local Host')}</text>
      <text y="21" text-anchor="middle" fill="#34d399" font-size="8">Ubuntu Linux</text>
    </g>
    ''')
    
    svg.append('</svg>')
    return "".join(svg)

if __name__ == "__main__":
    print("Testing Linux Topology Engine...")
    svg_out = build_network_topology_svg(
        "192.168.1.50",
        "192.168.1.1",
        "10:da:43:aa:bb:cc",
        [{"ip": "192.168.1.120", "mac": "aa:bb:cc:dd:ee:ff"}],
        [{"name": "Google DNS", "host": "8.8.8.8", "status": "ONLINE", "checkType": "TCP", "observedSla": 99.9}]
    )
    print(f"Generated SVG length: {len(svg_out)} chars.")
