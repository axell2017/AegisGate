#!/usr/bin/env python3
"""
VPN Kill-Switch + Toggle
========================
Quick restore normal internet if VPN causes issues.
Designed for toolbar/sonic-list integration.

Usage:
  python3 vpn_toggle.py kill      # Kill VPN, restore normal internet
  python3 vpn_toggle.py status    # Check VPN health
  python3 vpn_toggle.py watch     # Background watcher (notifications on drop)
  python3 vpn_toggle.py reconnect # Kill stale VPN + fresh connect
"""

import subprocess
import sys
import time
import json
from pathlib import Path

POOL_ROOT = Path(__file__).parent.resolve()
STATE_FILE = POOL_ROOT / "vpn_toggle_state.json"


def get_real_gateway():
    """Find the real (non-VPN) default gateway."""
    try:
        r = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.split("\n"):
            if "via" in line:
                parts = line.strip().split()
                idx = parts.index("via")
                gw = parts[idx + 1]
                iface = parts[parts.index("dev") + 1] if "dev" in parts else "?"
                return gw, iface
    except Exception:
        pass
    return None, None


def kill_vpn():
    """Kill VPN, remove tun0, restore normal routing."""
    print("🔌 Killing VPN...")
    
    # Kill all OpenVPN processes
    subprocess.run(["sudo", "killall", "openvpn"], capture_output=True, timeout=5)
    time.sleep(1)
    
    # Remove tun0
    subprocess.run(["sudo", "ip", "link", "del", "tun0"], capture_output=True, timeout=3)
    subprocess.run(["sudo", "ip", "link", "del", "wg0"], capture_output=True, timeout=3)
    
    # Restore default route
    gw, iface = get_real_gateway()
    if gw:
        subprocess.run(["sudo", "ip", "route", "del", "default"], capture_output=True, timeout=3)
        subprocess.run(["sudo", "ip", "route", "add", "default", "via", gw, "dev", iface], capture_output=True, timeout=3)
    
    # Clear VPN routing rules
    subprocess.run(["sudo", "iptables", "-t", "mangle", "-F", "OUTPUT"], capture_output=True, timeout=3)
    subprocess.run(["sudo", "iptables", "-t", "nat", "-F", "POSTROUTING"], capture_output=True, timeout=3)
    subprocess.run(["sudo", "ip", "rule", "del", "fwmark", "0x1"], capture_output=True, timeout=3)
    
    # Clear state
    STATE_FILE.unlink(missing_ok=True)
    
    print("✓ Normal internet restored")
    return True


def check_vpn_health():
    """Check if VPN is alive and routing."""
    status = {
        "vpn_up": False,
        "tun0_exists": False,
        "openvpn_running": False,
        "exit_ip": None,
        "internet_ok": False
    }
    
    # Check tun0
    r = subprocess.run(["ip", "link", "show", "tun0"], capture_output=True, text=True, timeout=3)
    if "UP" in r.stdout:
        status["tun0_exists"] = True
    
    # Check openvpn process
    r = subprocess.run(["pgrep", "-x", "openvpn"], capture_output=True, text=True, timeout=3)
    if r.returncode == 0 and r.stdout.strip():
        status["openvpn_running"] = True
    
    # Check internet
    import urllib.request
    try:
        req = urllib.request.Request("https://ifconfig.me", headers={"User-Agent": "curl/7.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            status["exit_ip"] = resp.read().decode().strip()
            status["internet_ok"] = True
    except Exception:
        pass
    
    status["vpn_up"] = status["tun0_exists"] and status["openvpn_running"]
    
    return status


def reconnect_vpn():
    """Kill stale VPN and reconnect fresh."""
    kill_vpn()
    time.sleep(2)
    
    # Use the pool manager to auto-connect
    r = subprocess.run(
        ["python3", str(POOL_ROOT / "vpn_pool.py"), "auto"],
        capture_output=True, text=True, timeout=45, cwd=str(POOL_ROOT)
    )
    
    if "✓ Connected" in r.stderr + r.stdout:
        print("✓ VPN reconnected")
        return True
    else:
        print("✗ VPN reconnect failed — internet stays direct")
        return False


def watch_vpn():
    """Background watcher — notify on VPN state changes."""
    print("🔍 VPN watcher started (Ctrl+C to stop)")
    last_state = None
    
    try:
        while True:
            state = check_vpn_health()
            
            if last_state is not None:
                # Detect state changes
                if state["vpn_up"] != last_state["vpn_up"]:
                    if state["vpn_up"]:
                        notify("🟢 VPN Connected", f"Exit IP: {state.get('exit_ip', 'unknown')}")
                        print(f"\n🟢 VPN CONNECTED — {state.get('exit_ip', '?')}")
                    else:
                        notify("🔴 VPN Dropped", "Falling back to direct connection")
                        print(f"\n🔴 VPN DROPPED — direct IP: {state.get('exit_ip', '?')}")
                
                if state["internet_ok"] != last_state["internet_ok"]:
                    if not state["internet_ok"]:
                        notify("⚠ Internet Lost", "No connectivity detected")
                        print("\n⚠ INTERNET LOST")
                    else:
                        notify("✓ Internet Restored", f"IP: {state.get('exit_ip', '?')}")
                        print(f"\n✓ INTERNET RESTORED — {state.get('exit_ip', '?')}")
            
            last_state = state
            
            # Save to state file for external tools to read
            with open(STATE_FILE, "w") as f:
                json.dump(state, f)
            
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nWatcher stopped.")


def notify(title, message):
    """Send desktop notification."""
    try:
        subprocess.run(
            ["notify-send", "--urgency=normal", title, message],
            capture_output=True, timeout=3
        )
    except Exception:
        pass


# ─── CLI ───────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: vpn_toggle.py [kill|status|watch|reconnect]")
        sys.exit(0)
    
    cmd = sys.argv[1].lower()
    
    if cmd == "kill":
        kill_vpn()
    
    elif cmd == "status":
        state = check_vpn_health()
        vpn_icon = "●" if state["vpn_up"] else "○"
        net_icon = "●" if state["internet_ok"] else "○"
        print(f"\n{vpn_icon} VPN: {'CONNECTED' if state['vpn_up'] else 'DOWN'}")
        print(f"{net_icon} Internet: {state['exit_ip'] or 'no connectivity'}")
        print(f"   tun0: {'exists' if state['tun0_exists'] else 'none'}")
        print(f"   openvpn: {'running' if state['openvpn_running'] else 'stopped'}")
        
        # JSON for toolbar integration
        if "--json" in sys.argv:
            print(json.dumps(state))
    
    elif cmd == "watch":
        watch_vpn()
    
    elif cmd == "reconnect":
        reconnect_vpn()
    
    else:
        print(f"Unknown: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
