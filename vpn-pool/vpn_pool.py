#!/usr/bin/env python3
"""
Aegis Shield VPN Pool Manager
==============================
Manages a pool of free VPN connections for programmatic routing.
Integrates with AegisGate for LLM traffic anonymization.

Providers:
  - VPN Gate (OpenVPN): 6000+ volunteer servers, free, no account
  - Free OpenVPN configs from vpnbook.com and similar
  - WireGuard free configs from various sources

Usage:
  python3 vpn_pool.py refresh           # Download fresh server lists
  python3 vpn_pool.py list              # List available VPN endpoints
  python3 vpn_pool.py connect <id>      # Connect to a specific VPN
  python3 vpn_pool.py disconnect        # Disconnect current VPN
  python3 vpn_pool.py cycle             # Cycle to next VPN in pool
  python3 vpn_pool.py status            # Show current VPN status
  python3 vpn_pool.py health            # Health check all pool members
  python3 vpn_pool.py auto              # Auto-select best VPN and connect
"""

import os
import sys
import json
import time
import csv
import base64
import signal
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

POOL_ROOT = Path(__file__).parent.resolve()
CONFIGS_DIR = POOL_ROOT / "configs"
LOGS_DIR = POOL_ROOT / "logs"
STATE_FILE = POOL_ROOT / "pool_state.json"
PID_FILE = POOL_ROOT / "openvpn.pid"
LOG_FILE = POOL_ROOT / "openvpn.log"

# ─── VPN Sources ───────────────────────────────────────────────────────────

VPN_SOURCES = {
    "vpngate": {
        "url": "https://www.vpngate.net/api/iphone/",
        "type": "openvpn",
        "description": "VPN Gate - University of Tsukuba volunteer network",
        "free": True,
        "account_required": False,
    },
    "vpnbook": {
        "url": "https://www.vpnbook.com/freevpn",
        "type": "openvpn",
        "description": "VPNBook - Free OpenVPN with rotating password",
        "free": True,
        "account_required": False,
        "note": "Password rotates weekly - check website",
    },
    "freevpn_me": {
        "url": "https://freevpn.me/accounts/",
        "type": "openvpn",
        "description": "FreeVPN.me - Free OpenVPN servers",
        "free": True,
        "account_required": False,
        "note": "Username: freevpnme, password rotates",
    },
}

# Built-in static fallback VPNs (for when API is unreachable)
STATIC_VPN_CONFIGS = [
    {
        "id": "vpngate_static_jp",
        "provider": "vpngate",
        "country": "JP",
        "type": "openvpn",
        "host": "219.100.37.98",
        "port": 443,
        "proto": "tcp",
    },
    {
        "id": "vpngate_static_kr",
        "provider": "vpngate",
        "country": "KR",
        "type": "openvpn",
        "host": "121.189.221.10",
        "port": 1443,
        "proto": "tcp",
    },
]


def log(msg: str) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{timestamp}] {msg}", file=sys.stderr)


def load_state() -> dict:
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"pool": [], "active": None, "history": [], "last_refresh": None}


def save_state(state: dict) -> None:
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2, default=str)


def fetch_vpngate_servers() -> list[dict]:
    """Fetch and parse VPN Gate server list. Returns list of server dicts."""
    log("Fetching VPN Gate server list...")
    
    try:
        req = urllib.request.Request(
            VPN_SOURCES["vpngate"]["url"],
            headers={"User-Agent": "AegisShield-VPN-Pool/1.0"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        log(f"VPN Gate fetch failed: {e}")
        return []

    # Parse CSV - skip the "*vpn_servers" marker line
    lines = raw.split("\n")
    if not lines or "*vpn_servers" not in lines[0]:
        log("Unexpected VPN Gate response format")
        return []

    # Find header line
    header_idx = None
    for i, line in enumerate(lines):
        if "HostName" in line and "OpenVPN_ConfigData_Base64" in line:
            header_idx = i
            break
    
    if header_idx is None:
        log("Could not find CSV header in VPN Gate response")
        return []

    servers = []
    reader = csv.DictReader(lines[header_idx:])
    for row in reader:
        try:
            b64_config = row.get("OpenVPN_ConfigData_Base64", "").strip()
            if not b64_config or len(b64_config) < 50:
                continue
            
            # Decode base64 to get the actual ovpn config
            try:
                config_text = base64.b64decode(b64_config).decode("utf-8", errors="replace")
            except Exception:
                continue

            ping_str = row.get("Ping", "0").strip()
            speed_str = row.get("Speed", "0").strip()
            
            try:
                ping = int(ping_str) if ping_str else 999
            except ValueError:
                ping = 999
            try:
                speed = int(speed_str) if speed_str else 0
            except ValueError:
                speed = 0

            hostname = row.get('HostName', 'unknown').strip()
            ip_addr = row.get('IP', '0').strip()
            # Use IP in ID to ensure uniqueness (many servers share hostnames)
            unique_id = f"vpngate_{hostname}_{ip_addr.replace('.', '-')}"

            server = {
                "id": unique_id,
                "provider": "vpngate",
                "type": "openvpn",
                "host": row.get("IP", "").strip(),
                "hostname": row.get("HostName", "").strip(),
                "country": row.get("CountryShort", "").strip(),
                "country_long": row.get("CountryLong", "").strip(),
                "score": int(row.get("Score", "0").strip() or "0"),
                "ping": ping,
                "speed_bps": speed,
                "sessions": int(row.get("NumVpnSessions", "0").strip() or "0"),
                "uptime_sec": int(row.get("Uptime", "0").strip() or "0"),
                "config_base64": b64_config,
                "config_ovpn": config_text,
            }
            servers.append(server)
        except Exception as e:
            continue

    log(f"Parsed {len(servers)} VPN Gate servers")
    return servers


def save_server_configs(servers: list[dict]) -> None:
    """Save OpenVPN config files for each server."""
    vpngate_dir = CONFIGS_DIR / "vpngate"
    vpngate_dir.mkdir(parents=True, exist_ok=True)
    
    for s in servers:
        cfg_path = vpngate_dir / f"{s['id']}.ovpn"
        try:
            # Decode if it's still base64
            if "config_ovpn" in s:
                config_text = s["config_ovpn"]
            elif "config_base64" in s:
                config_text = base64.b64decode(s["config_base64"]).decode("utf-8", errors="replace")
            else:
                continue
            
            # Don't inject route-noexec into config - we pass it via CLI flag
            # (Adding it to config breaks some OpenVPN versions)
            with open(cfg_path, "w") as f:
                f.write(config_text)
        except Exception as e:
            log(f"Failed to save config for {s['id']}: {e}")


def is_openvpn_running() -> bool:
    """Check if an OpenVPN process is currently running AND tun0 exists."""
    # Must have both: process AND tun0 interface
    has_process = False
    try:
        result = subprocess.run(
            ["pgrep", "-x", "openvpn"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            has_process = True
    except Exception:
        pass
    
    # Verify tun0 exists
    has_tun = False
    try:
        result = subprocess.run(
            ["ip", "link", "show", "tun0"],
            capture_output=True, text=True, timeout=5
        )
        has_tun = result.returncode == 0
    except Exception:
        pass
    
    if has_process and has_tun:
        return True
    
    # Cleanup: if process exists but no tun0, kill the stale process
    if has_process and not has_tun:
        try:
            subprocess.run(["sudo", "killall", "openvpn"], capture_output=True, timeout=5)
        except Exception:
            pass
    
    return False


def get_current_exit_ip() -> Optional[str]:
    """Get current public IP (may go through VPN)."""
    try:
        req = urllib.request.Request(
            "https://ifconfig.me",
            headers={"User-Agent": "curl/7.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode().strip()
    except Exception as e:
        try:
            req = urllib.request.Request(
                "https://api.ipify.org",
                headers={"User-Agent": "curl/7.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.read().decode().strip()
        except Exception:
            return None


def connect_openvpn(config_path: Path) -> bool:
    """Connect to an OpenVPN server using the given config."""
    if is_openvpn_running():
        log("OpenVPN already running, disconnecting first...")
        disconnect_vpn()
        time.sleep(2)

    # Run openvpn in foreground with a timeout — more reliable than daemon mode
    cmd = [
        "sudo", "openvpn",
        "--config", str(config_path),
        "--daemon",
        "--writepid", str(PID_FILE),
        "--log", str(LOG_FILE),
        "--script-security", "2",
        "--route-noexec",
        "--connect-retry", "1",
        "--connect-timeout", "10",
        "--connect-retry-max", "1",
    ]

    log(f"Starting OpenVPN (daemon, waiting for tun0)...")
    try:
        # With --daemon, openvpn forks and parent exits immediately.
        # Just fire-and-forget, then poll for tun0.
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            log(f"OpenVPN start failed: {result.stderr}")
            return False
        
        # Wait for tun0 interface (up to 25 seconds)
        for i in range(25):
            time.sleep(1)
            try:
                check = subprocess.run(
                    ["ip", "link", "show", "tun0"],
                    capture_output=True, timeout=3
                )
                if check.returncode == 0 and "UP" in check.stdout:
                    log("OpenVPN connected — tun0 is UP")
                    return True
            except Exception:
                pass
        
        # Timeout — kill daemon
        log("tun0 didn't appear within 25s, killing daemon...")
        subprocess.run(["sudo", "killall", "openvpn"], capture_output=True, timeout=5)
        return False
        
    except Exception as e:
        log(f"OpenVPN start error: {e}")
        return False


def connect_wireguard(config_path: Path) -> bool:
    """Connect using a WireGuard config."""
    try:
        result = subprocess.run(
            ["sudo", "wg-quick", "up", str(config_path)],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            log("WireGuard connection established")
            return True
        log(f"WireGuard failed: {result.stderr}")
        return False
    except Exception as e:
        log(f"WireGuard error: {e}")
        return False


def disconnect_vpn() -> bool:
    """Disconnect any active VPN connection."""
    disconnected = False
    
    # Kill all openvpn processes
    try:
        result = subprocess.run(
            ["sudo", "killall", "openvpn"],
            capture_output=True, timeout=5
        )
        if result.returncode == 0:
            disconnected = True
            log("Terminated OpenVPN processes")
    except Exception:
        pass
    
    # Clean up PID file
    PID_FILE.unlink(missing_ok=True)
    
    # Bring down any tun0
    try:
        subprocess.run(
            ["sudo", "ip", "link", "del", "tun0"],
            capture_output=True, timeout=5
        )
    except Exception:
        pass

    # Try WireGuard (down any wg-* interfaces)
    try:
        subprocess.run(
            ["sudo", "wg", "show"], capture_output=True, timeout=5
        )
        # Get active wg interfaces
        result = subprocess.run(
            ["sudo", "wg", "show", "interfaces"],
            capture_output=True, text=True, timeout=5
        )
        for iface in result.stdout.strip().split():
            if iface:
                subprocess.run(
                    ["sudo", "wg-quick", "down", iface],
                    capture_output=True, timeout=10
                )
                disconnected = True
                log(f"Brought down WireGuard interface {iface}")
    except Exception:
        pass

    return disconnected


def check_vpn_health(server: dict) -> dict:
    """Health check a VPN server (ping test)."""
    import subprocess
    
    host = server.get("host", "")
    result = {"id": server["id"], "reachable": False, "latency_ms": None}
    
    if not host:
        return result
    
    try:
        proc = subprocess.run(
            ["ping", "-c", "2", "-W", "2", host],
            capture_output=True, text=True, timeout=5
        )
        if proc.returncode == 0:
            # Parse avg latency
            for line in proc.stdout.split("\n"):
                if "rtt min/avg/max" in line:
                    avg = line.split("/")[4]
                    result["latency_ms"] = float(avg)
                    break
            result["reachable"] = True
    except Exception:
        pass
    
    return result


def cycle_vpn(state: dict) -> Optional[dict]:
    """Cycle to the next VPN in the pool."""
    pool = state.get("pool", [])
    if not pool:
        log("No VPNs in pool. Run 'refresh' first.")
        return None
    
    active = state.get("active")
    active_id = active.get("id") if active else None
    
    # Find next server in rotation
    if active_id:
        try:
            current_idx = next(i for i, s in enumerate(pool) if s["id"] == active_id)
            next_idx = (current_idx + 1) % len(pool)
        except StopIteration:
            next_idx = 0
    else:
        next_idx = 0
    
    server = pool[next_idx]
    return server


def filter_pool(servers: list[dict], min_uptime_hours: float = 0.5,
                max_ping: int = 200, countries: list[str] = None) -> list[dict]:
    """Filter server pool by quality criteria."""
    filtered = []
    for s in servers:
        ping = s.get("ping", 999)
        uptime_h = s.get("uptime_sec", 0) / 3600.0
        
        if ping > max_ping:
            continue
        if uptime_h < min_uptime_hours:
            continue
        if countries and s.get("country") not in countries:
            continue
        
        # Calculate quality score (lower ping + higher uptime = better)
        quality = (1.0 / (ping + 1)) * min(uptime_h, 48) * (s.get("speed_bps", 0) / 1e6 + 1)
        s["quality"] = round(quality, 4)
        filtered.append(s)
    
    filtered.sort(key=lambda s: s.get("quality", 0), reverse=True)
    return filtered


# ─── Commands ──────────────────────────────────────────────────────────────

def cmd_refresh(state: dict) -> dict:
    """Fetch fresh VPN server lists from all sources."""
    log("═" * 50)
    log("VPN Pool Refresh Started")
    
    all_servers = []
    
    # 1. VPN Gate
    vpngate_servers = fetch_vpngate_servers()
    if vpngate_servers:
        save_server_configs(vpngate_servers)
        all_servers.extend(vpngate_servers)
    
    # 2. Add static fallbacks if API failed
    if not all_servers:
        log("Using static fallback VPNs")
        all_servers = STATIC_VPN_CONFIGS
    
    # Filter and sort by quality
    pool = filter_pool(all_servers, min_uptime_hours=0.5, max_ping=200)
    
    if not pool:
        # Relax filters
        pool = filter_pool(all_servers, min_uptime_hours=0, max_ping=500)
    
    state["pool"] = pool[:50]  # Keep top 50
    state["last_refresh"] = datetime.now(timezone.utc).isoformat()
    state["total_available"] = len(all_servers)
    
    save_state(state)
    
    # Summary
    log(f"Total servers discovered: {len(all_servers)}")
    log(f"After filtering, top {len(pool)} in pool")
    if pool:
        countries = set(s.get("country", "??") for s in pool[:10])
        log(f"Top countries: {', '.join(sorted(countries))}")
        top = pool[0]
        log(f"Best server: {top['id']} ({top.get('country', '??')}) - ping={top.get('ping', '?')}ms")
    
    return state


def cmd_list(state: dict) -> None:
    """List available VPN servers in the pool."""
    pool = state.get("pool", [])
    active = state.get("active")
    active_id = active.get("id") if active else None
    
    if not pool:
        print("No VPN servers in pool. Run 'refresh' first.")
        return
    
    print(f"\n{'='*70}")
    print(f"  VPN Pool — {len(pool)} servers available")
    print(f"  Last refresh: {state.get('last_refresh', 'never')}")
    print(f"{'='*70}")
    print(f"{'#':>3} {'STATUS':6} {'PROVIDER':12} {'CC':3} {'PING':>6} {'HOST':18} {'ID'}")
    print(f"{'-'*3} {'-'*6} {'-'*12} {'-'*3} {'-'*6} {'-'*18} {'-'*20}")
    
    for i, s in enumerate(pool[:20]):
        status = "● LIVE" if s["id"] == active_id else "○"
        provider = s.get("provider", "?")
        cc = s.get("country", "??")
        ping = f"{s.get('ping', '?')}ms"
        host = s.get("host", "?")[:18]
        sid = s["id"][:30]
        print(f"{i:>3} {status:6} {provider:12} {cc:3} {ping:>6} {host:18} {sid}")
    
    if len(pool) > 20:
        print(f"  ... and {len(pool) - 20} more")
    print()


def cmd_status(state: dict) -> None:
    """Show current VPN connection status."""
    active = state.get("active")
    native_ip = get_current_exit_ip()
    
    print(f"\n{'='*50}")
    print(f"  Aegis Shield VPN Status")
    print(f"{'='*50}")
    
    if active:
        print(f"  VPN:       ● CONNECTED")
        print(f"  Provider:  {active.get('provider', '?')}")
        print(f"  Server:    {active.get('id', '?')}")
        print(f"  Country:   {active.get('country_long', '?')} ({active.get('country', '?')})")
        print(f"  Host:      {active.get('host', '?')}")
        print(f"  Ping:      {active.get('ping', '?')}ms")
        print(f"  Connected: {active.get('connected_at', '?')}")
        
        state["history"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "exit_ip": native_ip,
            "vpn_id": active["id"],
        })
        save_state(state)
    else:
        print(f"  VPN:       ○ DISCONNECTED")
    
    print(f"  Exit IP:   {native_ip or 'unknown'}")
    print(f"  PID file:  {'exists' if PID_FILE.exists() else 'none'}")
    print(f"  Pool size: {len(state.get('pool', []))}")
    print()


def cmd_connect(state: dict, server_id: str = None) -> None:
    """Connect to a specific VPN or auto-select best."""
    pool = state.get("pool", [])
    if not pool:
        print("No VPNs available. Run 'refresh' first.")
        sys.exit(1)
    
    # Prefer TCP servers by filtering
    tcp_pool = [s for s in pool if _is_tcp_server(s)]
    udp_pool = [s for s in pool if not _is_tcp_server(s)]
    ordered_pool = tcp_pool + udp_pool  # TCP first
    
    server = None
    if server_id:
        for s in ordered_pool:
            if server_id in s["id"]:
                server = s
                break
        if not server:
            try:
                idx = int(server_id)
                if 0 <= idx < len(ordered_pool):
                    server = ordered_pool[idx]
            except ValueError:
                pass
    
    if not server:
        # Auto-select: try TCP servers first, up to 3 attempts
        candidates = ordered_pool[:5]  # Try top 5
        for candidate in candidates:
            print(f"Trying: {candidate['id']} ({candidate.get('country', '??')})...")
            if _try_connect_server(state, candidate):
                return
        print("✗ All connection attempts failed")
        sys.exit(1)
    
    if not _try_connect_server(state, server):
        print("✗ Connection failed. Trying fallback servers...")
        for candidate in ordered_pool[:5]:
            if candidate["id"] != server["id"]:
                print(f"Fallback: {candidate['id']} ({candidate.get('country', '??')})...")
                if _try_connect_server(state, candidate):
                    return
        sys.exit(1)
    
def _is_tcp_server(server: dict) -> bool:
    """Check if a server uses TCP (more reliable than UDP behind NAT)."""
    config_text = server.get("config_ovpn", "")
    if not config_text:
        # Check the actual config file
        config_path = CONFIGS_DIR / "vpngate" / f"{server['id']}.ovpn"
        if config_path.exists():
            config_text = config_path.read_text(errors="replace")
    if not config_text:
        return False
    # Only check uncommented lines (comments often mention both proto tcp and proto udp)
    for line in config_text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("proto ") and not stripped.startswith(("#", ";")):
            return "tcp" in stripped.lower()
    return False


def _try_connect_server(state: dict, server: dict) -> bool:
    """Try to connect to a single server. Returns True on success."""
    # Determine config path
    if server["type"] == "openvpn":
        config_path = CONFIGS_DIR / "vpngate" / f"{server['id']}.ovpn"
        if not config_path.exists():
            # Try to regenerate
            if "config_ovpn" in server:
                config_path.parent.mkdir(parents=True, exist_ok=True)
                with open(config_path, "w") as f:
                    f.write(server["config_ovpn"])
            else:
                return False
        
        if connect_openvpn(config_path):
            server["connected_at"] = datetime.now(timezone.utc).isoformat()
            state["active"] = server
            save_state(state)
            time.sleep(1)
            new_ip = get_current_exit_ip()
            print(f"✓ Connected! Active IP: {new_ip}")
            return True
    
    elif server["type"] == "wireguard":
        config_path = CONFIGS_DIR / f"{server['id']}.conf"
        if connect_wireguard(config_path):
            server["connected_at"] = datetime.now(timezone.utc).isoformat()
            state["active"] = server
            save_state(state)
            return True
    
    return False


def cmd_disconnect(state: dict) -> None:
    """Disconnect from current VPN."""
    if not is_openvpn_running():
        print("No active VPN connection found.")
    else:
        disconnect_vpn()
        print("✓ VPN disconnected")
    
    if state.get("active"):
        state["active"]["disconnected_at"] = datetime.now(timezone.utc).isoformat()
        state["active"] = None
        save_state(state)


def cmd_cycle(state: dict) -> None:
    """Cycle to next VPN in pool."""
    server = cycle_vpn(state)
    if not server:
        return
    
    print(f"Cycling to: {server['id']} ({server.get('country', '??')})")
    if is_openvpn_running():
        disconnect_vpn()
        time.sleep(2)
    
    cmd_connect(state, server["id"])


def cmd_health(state: dict) -> None:
    """Run health checks on pool members."""
    pool = state.get("pool", [])
    if not pool:
        print("No VPNs in pool.")
        return
    
    print(f"Health checking {min(10, len(pool))} servers...")
    results = []
    for s in pool[:10]:
        h = check_vpn_health(s)
        results.append(h)
        status = "✓" if h["reachable"] else "✗"
        lat = f"{h['latency_ms']:.0f}ms" if h["latency_ms"] else "N/A"
        print(f"  {status} {s['id'][:40]:40} {lat}")
    
    reachable = sum(1 for r in results if r["reachable"])
    print(f"\n  {reachable}/{len(results)} reachable")


# ─── CLI ───────────────────────────────────────────────────────────────────

def print_usage():
    print("""
Aegis Shield VPN Pool Manager

Usage:
  python3 vpn_pool.py refresh        Fetch fresh VPN server lists
  python3 vpn_pool.py list           List available VPNs
  python3 vpn_pool.py status         Show current connection status
  python3 vpn_pool.py connect [id]   Connect to VPN (auto-select if no id)
  python3 vpn_pool.py disconnect     Disconnect current VPN
  python3 vpn_pool.py cycle          Cycle to next VPN in pool
  python3 vpn_pool.py health         Health check pool members
  python3 vpn_pool.py auto           Auto-select and connect to best VPN
""")


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)
    
    command = sys.argv[1].lower()
    state = load_state()
    
    if command == "refresh":
        cmd_refresh(state)
    
    elif command == "list":
        cmd_list(state)
    
    elif command == "status":
        cmd_status(state)
    
    elif command == "connect":
        server_id = sys.argv[2] if len(sys.argv) > 2 else None
        cmd_connect(state, server_id)
    
    elif command == "disconnect":
        cmd_disconnect(state)
    
    elif command == "cycle":
        cmd_cycle(state)
    
    elif command == "health":
        cmd_health(state)
    
    elif command == "auto":
        cmd_connect(state, None)
    
    else:
        print(f"Unknown command: {command}")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
