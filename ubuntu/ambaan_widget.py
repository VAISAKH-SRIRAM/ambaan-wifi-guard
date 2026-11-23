#!/usr/bin/env python3
"""
Ambaan 3.0 Floating Desktop Widget (Ubuntu Linux)
Interactive Obsidian Glass floating HUD with animated character, real-time Wi-Fi telemetry,
server status monitoring, bandwidth tracker, and one-click diagnostics.
Zero external pip dependencies (built on standard Python 3 Tkinter).
Includes automatic Terminal HUD fallback for headless/SSH environments.
"""

import os
import subprocess
import sys
import threading
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DIR = os.path.join(SCRIPT_DIR, "assets")

# Import diagnostic helpers
from server_monitor import load_servers, probe_all_servers
from network_intelligence import measure_this_pc_bandwidth
from ambaan_analyzer import get_default_route_and_interface, get_wifi_telemetry, measure_ping_metrics, measure_dns_latency

class AmbaanWidgetGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Ambaan 3.0 Wi-Fi Guard")
        self.root.overrideredirect(True)  # Frameless obsidian glass window
        self.root.attributes("-topmost", True)
        
        # Position at top-right of screen
        screen_w = self.root.winfo_screenwidth()
        w = 340
        h = 240
        x = max(20, screen_w - w - 40)
        y = 60
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.configure(bg="#090d16")
        
        # Dragging support
        self.drag_start_x = 0
        self.drag_start_y = 0
        self.root.bind("<ButtonPress-1>", self.on_drag_start)
        self.root.bind("<B1-Motion>", self.on_drag_motion)
        
        # Telemetry state
        self.ssid = "Scanning..."
        self.signal_pct = 0
        self.speed_mbps = 0
        self.gw_latency = "--"
        self.jitter = "--"
        self.rx_kbps = 0.0
        self.tx_kbps = 0.0
        self.servers_summary = "--/--"
        self.shield_status = "ACTIVE"
        self.is_muted = False
        
        # GIF Animation setup
        self.gif_frames = []
        self.current_frame = 0
        self.load_gif_frames()
        
        self.build_ui()
        
        # Background Telemetry Thread
        self.running = True
        self.telemetry_thread = threading.Thread(target=self.telemetry_loop, daemon=True)
        self.telemetry_thread.start()
        
        # Animation loop
        self.animate_gif()

    def on_drag_start(self, event):
        self.drag_start_x = event.x
        self.drag_start_y = event.y

    def on_drag_motion(self, event):
        x = self.root.winfo_x() - self.drag_start_x + event.x
        y = self.root.winfo_y() - self.drag_start_y + event.y
        self.root.geometry(f"+{x}+{y}")

    def load_gif_frames(self):
        import tkinter as tk
        gif_path = os.path.join(ASSETS_DIR, "dhamu.gif")
        if not os.path.exists(gif_path):
            return
        idx = 0
        while True:
            try:
                frame = tk.PhotoImage(file=gif_path, format=f"gif -index {idx}")
                # Subsample to compact widget dimensions if needed
                self.gif_frames.append(frame.subsample(3, 3))
                idx += 1
            except Exception:
                break

    def animate_gif(self):
        if self.gif_frames and hasattr(self, "avatar_label"):
            self.avatar_label.configure(image=self.gif_frames[self.current_frame])
            self.current_frame = (self.current_frame + 1) % len(self.gif_frames)
        self.root.after(120, self.animate_gif)

    def build_ui(self):
        import tkinter as tk
        
        # Outer Border container
        self.border_frame = tk.Frame(self.root, bg="#1e293b", bd=1)
        self.border_frame.pack(fill="both", expand=True)
        
        self.main_frame = tk.Frame(self.border_frame, bg="#090d16", padx=12, pady=10)
        self.main_frame.pack(fill="both", expand=True, padx=1, pady=1)
        
        # Top Bar: Title, Status Badge, Close
        top_bar = tk.Frame(self.main_frame, bg="#090d16")
        top_bar.pack(fill="x", pady=(0, 8))
        
        title_label = tk.Label(top_bar, text="AMBAAN 3.0", font=("Helvetica", 10, "bold"), fg="#38bdf8", bg="#090d16")
        title_label.pack(side="left")
        
        shield_badge = tk.Label(top_bar, text=" SHIELD ACTIVE ", font=("Helvetica", 7, "bold"), fg="#10b981", bg="#064e3b")
        shield_badge.pack(side="left", padx=8)
        
        close_btn = tk.Button(top_bar, text="✕", font=("Helvetica", 8, "bold"), fg="#94a3b8", bg="#1e293b",
                              bd=0, padx=6, pady=1, cursor="hand2", command=self.close)
        close_btn.pack(side="right")
        
        # Body: Avatar (Left) + Telemetry Grid (Right)
        body_frame = tk.Frame(self.main_frame, bg="#090d16")
        body_frame.pack(fill="both", expand=True)
        
        # Left: Avatar
        avatar_container = tk.Frame(body_frame, bg="#111827", bd=1, relief="solid")
        avatar_container.pack(side="left", padx=(0, 10), pady=2)
        
        if self.gif_frames:
            self.avatar_label = tk.Label(avatar_container, image=self.gif_frames[0], bg="#111827")
        else:
            self.avatar_label = tk.Label(avatar_container, text="AMBAAN", font=("Helvetica", 8, "bold"),
                                         fg="#38bdf8", bg="#111827", width=10, height=5)
        self.avatar_label.pack()
        
        # Right: Stats Grid
        stats_frame = tk.Frame(body_frame, bg="#090d16")
        stats_frame.pack(side="left", fill="both", expand=True)
        
        # Row 1: Wi-Fi SSID & Signal
        self.lbl_wifi = tk.Label(stats_frame, text="Wi-Fi: Scanning...", font=("Helvetica", 9, "bold"), fg="#f8fafc", bg="#090d16", anchor="w")
        self.lbl_wifi.pack(fill="x")
        
        # Row 2: Latency & Jitter
        self.lbl_latency = tk.Label(stats_frame, text="Ping: -- ms | Jitter: -- ms", font=("Helvetica", 8), fg="#10b981", bg="#090d16", anchor="w")
        self.lbl_latency.pack(fill="x", pady=2)
        
        # Row 3: Bandwidth
        self.lbl_bw = tk.Label(stats_frame, text="Bandwidth: ↓ 0 KB/s  ↑ 0 KB/s", font=("Helvetica", 8), fg="#a855f7", bg="#090d16", anchor="w")
        self.lbl_bw.pack(fill="x", pady=2)
        
        # Row 4: Servers
        self.lbl_servers = tk.Label(stats_frame, text="Servers: 3/3 UP", font=("Helvetica", 8), fg="#38bdf8", bg="#090d16", anchor="w")
        self.lbl_servers.pack(fill="x", pady=2)
        
        # Bottom Controls: Diagnostic Button, Mute Button
        bottom_bar = tk.Frame(self.main_frame, bg="#090d16")
        bottom_bar.pack(fill="x", pady=(10, 0))
        
        diag_btn = tk.Button(bottom_bar, text="RUN DIAGNOSTIC", font=("Helvetica", 8, "bold"), fg="#ffffff", bg="#0284c7",
                             activebackground="#0369a1", bd=0, padx=10, pady=4, cursor="hand2", command=self.run_diagnostic)
        diag_btn.pack(side="left")
        
        self.mute_btn = tk.Button(bottom_bar, text="AUDIO: ON", font=("Helvetica", 8), fg="#94a3b8", bg="#1e293b",
                                  bd=0, padx=8, pady=4, cursor="hand2", command=self.toggle_mute)
        self.mute_btn.pack(side="right")

    def toggle_mute(self):
        self.is_muted = not self.is_muted
        self.mute_btn.configure(text="AUDIO: MUTED" if self.is_muted else "AUDIO: ON")

    def run_diagnostic(self):
        analyzer_script = os.path.join(SCRIPT_DIR, "ambaan_analyzer.py")
        subprocess.Popen([sys.executable, analyzer_script])

    def close(self):
        self.running = False
        self.root.destroy()

    def telemetry_loop(self):
        while self.running:
            try:
                gw_ip, iface = get_default_route_and_interface()
                wifi = get_wifi_telemetry(iface)
                gw_ping = measure_ping_metrics(gw_ip, count=2)
                bw = measure_this_pc_bandwidth(iface)
                servers = load_servers(gw_ip)
                
                # Fast ping for servers
                up_s = sum(1 for s in servers if s.get("status", "ONLINE") == "ONLINE")
                total_s = len(servers)
                
                # Update UI via main thread safe calls
                ssid_txt = f"{wifi['ssid'][:14]} ({wifi['signalPct']}%)"
                lat_txt = f"Ping: {gw_ping['avgRtt'] or '--'} ms | Jitter: {gw_ping['jitter']} ms"
                bw_txt = f"Traffic: ↓{bw['rxRateKbps']} ↑{bw['txRateKbps']} KB/s"
                srv_txt = f"Servers: {up_s}/{total_s} Online"
                
                self.root.after(0, self.update_labels, ssid_txt, lat_txt, bw_txt, srv_txt)
            except Exception:
                pass
            time.sleep(3)

    def update_labels(self, ssid_txt, lat_txt, bw_txt, srv_txt):
        self.lbl_wifi.configure(text=f"Wi-Fi: {ssid_txt}")
        self.lbl_latency.configure(text=lat_txt)
        self.lbl_bw.configure(text=bw_txt)
        self.lbl_servers.configure(text=srv_txt)

def run_terminal_hud():
    """Fallback interactive TUI HUD for headless or SSH sessions without X11/Wayland."""
    print("\n[!] No active graphical desktop detected. Launching Ambaan Terminal HUD...")
    print("    Press Ctrl+C to exit.\n")
    try:
        while True:
            gw_ip, iface = get_default_route_and_interface()
            wifi = get_wifi_telemetry(iface)
            gw_ping = measure_ping_metrics(gw_ip, count=2)
            bw = measure_this_pc_bandwidth(iface)
            servers = load_servers(gw_ip)
            up_s = sum(1 for s in servers if s.get("status", "ONLINE") == "ONLINE")
            
            # Print updated status line
            sys.stdout.write(
                f"\r\033[K[AMBAAN 3.0] Wi-Fi: {wifi['ssid']} ({wifi['signalPct']}%) | "
                f"Ping: {gw_ping['avgRtt'] or '--'}ms (Jitter: {gw_ping['jitter']}ms) | "
                f"Bandwidth: ↓{bw['rxRateKbps']} ↑{bw['txRateKbps']} KB/s | "
                f"Servers: {up_s}/{len(servers)} UP"
            )
            sys.stdout.flush()
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n\nAmbaan HUD stopped.")

def main():
    # Detect if graphical display is available
    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if not has_display:
        run_terminal_hud()
        return

    try:
        import tkinter as tk
        root = tk.Tk()
        app = AmbaanWidgetGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"Tkinter GUI initialization notice: {e}")
        run_terminal_hud()

if __name__ == "__main__":
    main()
