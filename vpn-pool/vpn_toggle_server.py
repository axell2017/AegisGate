#!/usr/bin/env python3
"""
VPN Toggle HTTP Server
======================
Tiny HTTP server for Sonic List toolbar VPN button.
Serves status JSON + executes kill/reconnect commands.

Usage:
  python3 vpn_toggle_server.py
  # Serves on :9217
  # GET  /vpn-status    → {"connected": true/false}
  # POST /kill-vpn       → kills VPN, restores internet
  # POST /reconnect-vpn  → reconnects VPN
"""

import json
import subprocess
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

POOL_ROOT = Path(__file__).parent.resolve()
PORT = 9217


class VPNHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/vpn-status" or self.path == "/":
            status = check_status()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(status).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path == "/kill-vpn":
            result = kill_vpn()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"killed": result}).encode())
        
        elif self.path == "/reconnect-vpn":
            result = reconnect_vpn()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"reconnected": result}).encode())
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
    
    def log_message(self, format, *args):
        pass  # Silent


def check_status():
    """Quick VPN health check."""
    connected = False
    try:
        r = subprocess.run(["pgrep", "-x", "openvpn"], capture_output=True, text=True, timeout=3)
        if r.returncode == 0 and r.stdout.strip():
            r2 = subprocess.run(["ip", "link", "show", "tun0"], capture_output=True, text=True, timeout=3)
            if "UP" in r2.stdout:
                connected = True
    except Exception:
        pass
    return {"connected": connected}


def kill_vpn():
    """Run kill-switch."""
    r = subprocess.run(
        ["python3", str(POOL_ROOT / "vpn_toggle.py"), "kill"],
        capture_output=True, text=True, timeout=15
    )
    return r.returncode == 0


def reconnect_vpn():
    """Reconnect VPN."""
    r = subprocess.run(
        ["python3", str(POOL_ROOT / "vpn_toggle.py"), "reconnect"],
        capture_output=True, text=True, timeout=45
    )
    return r.returncode == 0


def main():
    server = HTTPServer(("127.0.0.1", PORT), VPNHandler)
    print(f"VPN Toggle Server → http://localhost:{PORT}")
    print("  GET  /vpn-status    → status JSON")
    print("  POST /kill-vpn       → kill VPN")
    print("  POST /reconnect-vpn  → reconnect")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.shutdown()


if __name__ == "__main__":
    main()
