#!/usr/bin/env python3
"""
Aegis Shield VPN Routing Layer
===============================
Programmatic VPN routing using Linux policy routing.
Routes specific traffic (AegisGate LLM, specific ports/apps) through active VPN.

Usage:
  python3 vpn_route.py route <port>      Route traffic on port through VPN
  python3 vpn_route.py unroute <port>    Remove VPN routing for port
  python3 vpn_route.py status            Show current routing rules
  python3 vpn_route.py isolate <port>    Force port through VPN (kill-switch)
  python3 vpn_route.py reset             Remove all VPN routing rules
"""

import subprocess
import sys
import os
import json
from pathlib import Path

POOL_ROOT = Path(__file__).parent.resolve()
ROUTING_STATE = POOL_ROOT / "routing" / "routing_state.json"
VPN_ROUTE_TABLE = 100  # Custom routing table ID for VPN traffic
VPN_FWMARK = 0x1       # Firewall mark for VPN-bound packets


def run(cmd: list[str], check: bool = False, timeout: int = 10) -> subprocess.CompletedProcess:
    """Run a command with sudo, return result."""
    full_cmd = ["sudo"] + cmd
    return subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)


def get_vpn_interface() -> str | None:
    """Detect active VPN interface (tun0, wg0, etc.)."""
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            for iface in ["tun0", "wg0", "tap0"]:
                if f": {iface}:" in line and "UP" in line:
                    return iface
    except Exception:
        pass
    return None


def get_vpn_gateway(iface: str) -> str | None:
    """Get the VPN gateway IP for an interface."""
    try:
        # For OpenVPN tun, gateway is the peer address
        result = subprocess.run(
            ["ip", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            if "peer" in line and "inet" in line:
                # inet X.X.X.X peer Y.Y.Y.Y/32
                parts = line.strip().split()
                for i, p in enumerate(parts):
                    if p == "peer" and i + 1 < len(parts):
                        return parts[i + 1].split("/")[0]
    except Exception:
        pass
    
    # Fallback: try route
    try:
        result = subprocess.run(
            ["ip", "route", "show", "dev", iface],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            parts = line.strip().split()
            if "via" in parts:
                idx = parts.index("via")
                return parts[idx + 1]
    except Exception:
        pass
    
    return None


def get_real_default_gateway() -> str | None:
    """Get the real (non-VPN) default gateway."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            if "via" in line and "tun" not in line and "wg" not in line:
                parts = line.strip().split()
                idx = parts.index("via")
                return parts[idx + 1]
    except Exception:
        pass
    return None


def detect_current_ip() -> str | None:
    """Detect current public IP."""
    import urllib.request
    try:
        req = urllib.request.Request("https://ifconfig.me", headers={"User-Agent": "curl/7.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode().strip()
    except Exception:
        try:
            req = urllib.request.Request("https://api.ipify.org")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.read().decode().strip()
        except Exception:
            return None


def setup_vpn_routing_table(iface: str, gateway: str) -> bool:
    """Initialize the custom VPN routing table."""
    # Check if table already exists
    result = run(["ip", "route", "show", "table", str(VPN_ROUTE_TABLE)])
    if result.returncode == 0 and result.stdout.strip():
        # Flush old entries
        run(["ip", "route", "flush", "table", str(VPN_ROUTE_TABLE)])
    
    # Add default route through VPN in our custom table
    r = run([
        "ip", "route", "add", "default", "via", gateway, "dev", iface,
        "table", str(VPN_ROUTE_TABLE)
    ])
    if r.returncode != 0:
        print(f"Failed to add VPN route: {r.stderr}")
        return False
    
    return True


def route_port_through_vpn(port: int, iface: str) -> bool:
    """Route traffic on a specific port through the VPN using policy routing."""
    gateway = get_vpn_gateway(iface)
    if not gateway:
        print(f"✗ Cannot determine VPN gateway for {iface}")
        return False
    
    print(f"Routing port {port} through {iface} (gw: {gateway})...")
    
    # 1. Set up the VPN routing table
    if not setup_vpn_routing_table(iface, gateway):
        return False
    
    # 2. Add fwmark rule to direct marked packets to VPN table
    run([
        "ip", "rule", "add", "fwmark", str(VPN_FWMARK),
        "table", str(VPN_ROUTE_TABLE)
    ])
    
    # 3. Use iptables to mark packets going to/from this port
    # Outgoing: mark packets destined for port
    run([
        "iptables", "-t", "mangle", "-A", "OUTPUT",
        "-p", "tcp", "--dport", str(port),
        "-j", "MARK", "--set-mark", str(VPN_FWMARK)
    ])
    
    # 4. Enable NAT/masquerade on VPN interface (so return packets come back)
    run([
        "iptables", "-t", "nat", "-A", "POSTROUTING",
        "-o", iface, "-j", "MASQUERADE"
    ])
    
    # 5. Save state
    state = load_routing_state()
    state.setdefault("routes", []).append({
        "port": port,
        "interface": iface,
        "gateway": gateway,
        "added_at": str(subprocess.run(["date", "-Iseconds"], capture_output=True, text=True).stdout.strip()),
    })
    save_routing_state(state)
    
    print(f"✓ Port {port} now routed through VPN ({iface})")
    return True


def unroute_port(port: int) -> bool:
    """Remove VPN routing for a specific port."""
    print(f"Removing VPN routing for port {port}...")
    
    # Remove iptables rules
    run([
        "iptables", "-t", "mangle", "-D", "OUTPUT",
        "-p", "tcp", "--dport", str(port),
        "-j", "MARK", "--set-mark", str(VPN_FWMARK)
    ])
    
    # Don't remove the table/rule if other ports may still use it
    
    state = load_routing_state()
    state["routes"] = [r for r in state.get("routes", []) if r["port"] != port]
    save_routing_state(state)
    
    print(f"✓ Routing removed for port {port}")
    return True


def isolate_port(port: int, iface: str) -> bool:
    """Kill-switch mode: port ONLY works through VPN, blocks direct access."""
    if not route_port_through_vpn(port, iface):
        return False
    
    # Block direct (non-VPN) access to this port
    real_gw = get_real_default_gateway()
    if real_gw:
        real_iface = None
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            if "dev" in line:
                real_iface = line.split("dev")[-1].strip().split()[0]
                break
        
        if real_iface and real_iface != iface:
            run([
                "iptables", "-A", "OUTPUT", "-o", real_iface,
                "-p", "tcp", "--dport", str(port), "-j", "DROP"
            ])
            print(f"✓ Kill-switch: port {port} blocked on {real_iface}")
    
    return True


def reset_routing() -> None:
    """Remove all VPN routing rules."""
    print("Resetting all VPN routing...")
    
    # Flush VPN route table
    run(["ip", "route", "flush", "table", str(VPN_ROUTE_TABLE)])
    
    # Remove fwmark rule
    run(["ip", "rule", "del", "fwmark", str(VPN_FWMARK), "table", str(VPN_ROUTE_TABLE)])
    
    # Flush iptables mangle OUTPUT chain for our mark
    run(["iptables", "-t", "mangle", "-F", "OUTPUT"])
    
    # Flush NAT POSTROUTING for masquerade
    run(["iptables", "-t", "nat", "-F", "POSTROUTING"])
    
    # Remove any DROP rules
    run(["iptables", "-F", "OUTPUT"])
    
    # Clear state
    ROUTING_STATE.unlink(missing_ok=True)
    
    print("✓ All VPN routing cleared")


def show_status() -> None:
    """Display current routing status."""
    iface = get_vpn_interface()
    
    print(f"\n{'='*60}")
    print(f"  Aegis Shield VPN Routing")
    print(f"{'='*60}")
    print(f"  VPN Interface:  {iface or '○ NONE'}")
    
    if iface:
        gw = get_vpn_gateway(iface)
        print(f"  VPN Gateway:    {gw or 'unknown'}")
        
        # Show routing table
        result = subprocess.run(
            ["ip", "route", "show", "table", str(VPN_ROUTE_TABLE)],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip():
            print(f"  VPN Route Table:")
            for line in result.stdout.strip().split("\n"):
                print(f"    {line}")
    
    # Show current IPs
    direct_ip = detect_current_ip()
    print(f"\n  Direct Exit IP: {direct_ip or 'unknown'}")
    
    # Show routed ports
    state = load_routing_state()
    routes = state.get("routes", [])
    if routes:
        print(f"\n  Routed Ports ({len(routes)}):")
        for r in routes:
            print(f"    :{r['port']} → {r['interface']} (gw: {r['gateway']})")
    
    # Show iptables rules
    result = subprocess.run(
        ["iptables", "-t", "mangle", "-L", "OUTPUT", "-n"],
        capture_output=True, text=True, timeout=5
    )
    if "MARK" in result.stdout:
        print(f"\n  iptables Mark Rules:")
        for line in result.stdout.split("\n"):
            if "MARK" in line:
                print(f"    {line.strip()}")
    
    print()


# ─── State ─────────────────────────────────────────────────────────────────

def load_routing_state() -> dict:
    if ROUTING_STATE.exists():
        with open(ROUTING_STATE) as f:
            return json.load(f)
    return {"routes": []}


def save_routing_state(state: dict) -> None:
    ROUTING_STATE.parent.mkdir(parents=True, exist_ok=True)
    with open(ROUTING_STATE, "w") as f:
        json.dump(state, f, indent=2)


# ─── CLI ───────────────────────────────────────────────────────────────────

def print_usage():
    print("""
Aegis Shield VPN Routing

Usage:
  python3 vpn_route.py status            Show routing status
  python3 vpn_route.py route <port>      Route traffic on port through VPN
  python3 vpn_route.py unroute <port>    Remove VPN routing for port
  python3 vpn_route.py isolate <port>    Force port through VPN (kill-switch)
  python3 vpn_route.py reset             Remove all VPN routing

Example:
  python3 vpn_route.py route 18080      # Route AegisGate through VPN
  python3 vpn_route.py route 8080       # Route app on 8080 through VPN
""")


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)
    
    command = sys.argv[1].lower()
    
    if command == "status":
        show_status()
    
    elif command == "route":
        if len(sys.argv) < 3:
            print("Usage: vpn_route.py route <port>")
            sys.exit(1)
        port = int(sys.argv[2])
        iface = get_vpn_interface()
        if not iface:
            print("✗ No active VPN interface found. Connect a VPN first.")
            sys.exit(1)
        route_port_through_vpn(port, iface)
    
    elif command == "unroute":
        if len(sys.argv) < 3:
            print("Usage: vpn_route.py unroute <port>")
            sys.exit(1)
        port = int(sys.argv[2])
        unroute_port(port)
    
    elif command == "cover":
        # Route a named service through VPN
        service = sys.argv[2] if len(sys.argv) > 2 else "aegis"
        iface = get_vpn_interface()
        if not iface:
            print("✗ No active VPN interface found. Connect a VPN first.")
            sys.exit(1)
        
        services = {
            "aegis": [18080],
            "hermes": [18080, 8080, 3000],  # Common Hermes ports
            "web": [80, 443],
            "all": [],  # handled separately
        }
        
        ports = services.get(service, [])
        if service == "all":
            print("⚠ Routing ALL traffic through VPN is risky — if VPN drops, internet goes down.")
            print("  Recommended: use 'cover hermes' or 'cover aegis' instead.")
            confirm = input("  Proceed? [y/N] ").strip().lower()
            if confirm != 'y':
                return
            # Change default route to VPN (careful!)
            gateway = get_vpn_gateway(iface)
            if gateway:
                subprocess.run(["sudo", "ip", "route", "replace", "default", "via", gateway, "dev", iface])
                print(f"✓ Default route now through VPN ({iface})")
            return
        
        for port in ports:
            route_port_through_vpn(port, iface)
        
        print(f"\n✓ {service} traffic now routed through VPN ({iface})")
        print(f"  Services covered: {ports}")
        print(f"  ⚠ This conversation is still DIRECT (not through VPN)")
        print(f"  To route everything: vpn_route.py cover all")
    
    elif command == "isolate":
        if len(sys.argv) < 3:
            print("Usage: vpn_route.py isolate <port>")
            sys.exit(1)
        port = int(sys.argv[2])
        iface = get_vpn_interface()
        if not iface:
            print("✗ No active VPN interface found.")
            sys.exit(1)
        isolate_port(port, iface)
    
    elif command == "reset":
        reset_routing()
    
    else:
        print(f"Unknown command: {command}")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
