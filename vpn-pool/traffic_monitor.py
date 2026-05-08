#!/usr/bin/env python3
"""
Aegis Shield Traffic Monitor
=============================
Live traffic visibility — request counts, model usage, VPN status, response times.
Persists between sessions via timeseries CSV. Agentic query support.

Usage:
  python3 traffic_monitor.py status     # Current traffic snapshot
  python3 traffic_monitor.py watch      # Live 5s refresh
  python3 traffic_monitor.py query      # Agentic query mode
  python3 traffic_monitor.py history    # Last 24h summary
  python3 traffic_monitor.py spikes     # Traffic spike detection
"""

import json
import csv
import time
import sys
import subprocess
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
import urllib.request

MONITOR_ROOT = Path(__file__).parent.resolve()
AUDIT_LOG = Path.home() / "AegisGate" / "logs" / "audit.jsonl"
TIMESERIES_CSV = Path.home() / "AegisGate" / "monitoring" / "traffic_timeseries.csv"
VPN_STATE = Path.home() / "AegisGate" / "vpn-pool" / "pool_state.json"
MESH_API = "http://localhost:9337"
AEGIS_API = "http://localhost:18080"
HISTORY_WINDOW = timedelta(hours=24)


def get_vpn_status() -> dict:
    """Get current VPN state."""
    status = {"connected": False, "exit_ip": None, "interface": None, "country": None}
    
    # Check tun0
    try:
        r = subprocess.run(["ip", "link", "show", "tun0"], capture_output=True, text=True, timeout=3)
        if "UP" in r.stdout:
            status["connected"] = True
            status["interface"] = "tun0"
    except Exception:
        pass
    
    # Get VPN exit IP
    try:
        r = subprocess.run(["ip", "addr", "show", "tun0"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.split("\n"):
            if "inet " in line and "peer" in line:
                parts = line.strip().split()
                for i, p in enumerate(parts):
                    if p == "peer" and i + 1 < len(parts):
                        status["gateway"] = parts[i + 1].split("/")[0]
    except Exception:
        pass
    
    # Get country from VPN state
    if VPN_STATE.exists():
        with open(VPN_STATE) as f:
            vs = json.load(f)
            active = vs.get("active", {})
            if active:
                status["country"] = active.get("country_long", active.get("country", "?"))
                status["provider"] = active.get("provider", "?")
                status["host"] = active.get("host", "?")
    
    return status


def get_mesh_status() -> dict:
    """Get mesh-llm peer and model status."""
    status = {"api_up": False, "peers": 0, "hosts": 0, "models": []}
    
    try:
        req = urllib.request.Request(f"{MESH_API}/v1/models")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            status["api_up"] = True
            status["models"] = [m["id"] for m in data.get("data", [])]
    except Exception:
        pass
    
    try:
        req = urllib.request.Request(f"http://localhost:3131/api/status")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            peers = data.get("peers", [])
            status["peers"] = len(peers)
            status["hosts"] = sum(1 for p in peers if p.get("state") == "serving")
            status["mesh_name"] = data.get("mesh_id", "?")[:12]
    except Exception:
        pass
    
    return status


def get_aegis_status() -> dict:
    """Get AegisGate health and recent traffic."""
    status = {"healthy": False, "recent_requests": 0, "blocks": 0, "redactions": 0}
    
    try:
        req = urllib.request.Request(f"{AEGIS_API}/health")
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                status["healthy"] = True
    except Exception:
        pass
    
    # Parse recent audit log
    if AUDIT_LOG.exists():
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        try:
            with open(AUDIT_LOG) as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                        ts = entry.get("timestamp", "")
                        if ts:
                            t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                            if t > cutoff:
                                status["recent_requests"] += 1
                                if entry.get("action") == "block":
                                    status["blocks"] += 1
                                if entry.get("redactions", 0) > 0:
                                    status["redactions"] += entry.get("redactions", 0)
                    except (json.JSONDecodeError, ValueError):
                        pass
        except Exception:
            pass
    
    return status


def get_iptables_rules() -> list:
    """Get active VPN routing rules."""
    rules = []
    try:
        r = subprocess.run(
            ["sudo", "iptables", "-t", "mangle", "-L", "OUTPUT", "-n"],
            capture_output=True, text=True, timeout=5
        )
        for line in r.stdout.split("\n"):
            if "MARK" in line and "set" in line:
                rules.append(line.strip())
    except Exception:
        pass
    return rules


def detect_spikes() -> list:
    """Detect traffic spikes from audit log."""
    if not AUDIT_LOG.exists():
        return []
    
    # Group requests by 5-minute window
    windows = defaultdict(int)
    cutoff = datetime.now(timezone.utc) - HISTORY_WINDOW
    
    try:
        with open(AUDIT_LOG) as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    ts = entry.get("timestamp", "")
                    if ts:
                        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        if t > cutoff:
                            window_key = t.replace(second=0, microsecond=0, minute=t.minute - t.minute % 5)
                            windows[window_key] += 1
                except Exception:
                    pass
    except Exception:
        pass
    
    if not windows:
        return []
    
    # Find windows > 2x the median
    counts = list(windows.values())
    counts.sort()
    median = counts[len(counts) // 2] if counts else 0
    threshold = max(median * 2, 5)  # at least 5 requests
    
    spikes = []
    for window, count in sorted(windows.items()):
        if count >= threshold:
            spikes.append({
                "time": window.isoformat(),
                "requests": count,
                "baseline": median,
                "ratio": round(count / max(median, 1), 1)
            })
    
    return spikes[-10:]  # Last 10 spikes


def save_timeseries(snapshot: dict) -> None:
    """Append traffic snapshot to persistent timeseries CSV."""
    TIMESERIES_CSV.parent.mkdir(parents=True, exist_ok=True)
    
    fields = [
        "timestamp", "vpn_connected", "mesh_peers", "mesh_hosts", "mesh_models",
        "aegis_healthy", "recent_requests", "blocks", "redactions",
        "routing_rules", "vpn_country"
    ]
    
    row = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "vpn_connected": int(snapshot["vpn"]["connected"]),
        "mesh_peers": snapshot["mesh"]["peers"],
        "mesh_hosts": snapshot["mesh"]["hosts"],
        "mesh_models": len(snapshot["mesh"]["models"]),
        "aegis_healthy": int(snapshot["aegis"]["healthy"]),
        "recent_requests": snapshot["aegis"]["recent_requests"],
        "blocks": snapshot["aegis"]["blocks"],
        "redactions": snapshot["aegis"]["redactions"],
        "routing_rules": len(snapshot["iptables"]),
        "vpn_country": snapshot["vpn"].get("country", ""),
    }
    
    file_exists = TIMESERIES_CSV.exists()
    with open(TIMESERIES_CSV, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


def load_history(hours: int = 24) -> list:
    """Load traffic timeseries history."""
    if not TIMESERIES_CSV.exists():
        return []
    
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = []
    with open(TIMESERIES_CSV) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                t = datetime.fromisoformat(row["timestamp"])
                if t > cutoff:
                    row["_parsed_time"] = t
                    rows.append(row)
            except (ValueError, KeyError):
                pass
    return rows


# ─── Display ───────────────────────────────────────────────────────────────

def print_status():
    """Print live traffic snapshot."""
    vpn = get_vpn_status()
    mesh = get_mesh_status()
    aegis = get_aegis_status()
    rules = get_iptables_rules()
    spikes = detect_spikes()
    
    snapshot = {"vpn": vpn, "mesh": mesh, "aegis": aegis, "iptables": rules}
    save_timeseries(snapshot)
    
    vpn_icon = "●" if vpn["connected"] else "○"
    mesh_icon = "●" if mesh["api_up"] else "○"
    aegis_icon = "●" if aegis["healthy"] else "○"
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║              Aegis Shield — Traffic Monitor                   ║
╠══════════════════════════════════════════════════════════════╣
║  {vpn_icon} VPN       {vpn['connected'] and '● CONNECTED' or '○ DISCONNECTED':<30} {vpn.get('country','?'):>10} ║
║           Provider: {vpn.get('provider','?'):<20} Host: {vpn.get('host','?'):<15} ║
║                                                              ║
║  {mesh_icon} mesh-llm  {mesh['api_up'] and '● ACTIVE' or '○ DOWN':<30} {mesh['mesh_name']:>10} ║
║           Peers: {mesh['peers']:<5} Hosts: {mesh['hosts']:<5} Models: {len(mesh['models']):<5}            ║
║                                                              ║
║  {aegis_icon} AegisGate {aegis['healthy'] and '● HEALTHY' or '○ DOWN':<30} {'':>10} ║
║           5min requests: {aegis['recent_requests']:<5} Blocks: {aegis['blocks']:<5} Redactions: {aegis['redactions']:<5}     ║
╠══════════════════════════════════════════════════════════════╣
║  Routing Rules ({len(rules)}):""")
    
    for r in rules:
        print(f"║    {r[:55]}")
    
    print("╠══════════════════════════════════════════════════════════════╣")
    
    if spikes:
        print("║  Recent Traffic Spikes:")
        for s in spikes[-3:]:
            print(f"║    {s['time'][:16]} | {s['requests']} req | {s['ratio']}x baseline")
    
    # Model list
    if mesh["models"]:
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║  Available Models:")
        for m in mesh["models"][:7]:
            print(f"║    • {m[:52]}")
        if len(mesh["models"]) > 7:
            print(f"║    ... and {len(mesh['models']) - 7} more")
    
    print("╚══════════════════════════════════════════════════════════════╝")
    
    return snapshot


def print_history(hours: int = 24):
    """Print traffic history summary."""
    rows = load_history(hours)
    if not rows:
        print(f"No traffic data for last {hours}h")
        return
    
    total_requests = sum(int(r.get("recent_requests", 0)) for r in rows)
    total_blocks = sum(int(r.get("blocks", 0)) for r in rows)
    total_redactions = sum(int(r.get("redactions", 0)) for r in rows)
    vpn_uptime = sum(int(r.get("vpn_connected", 0)) for r in rows)
    mesh_avg = sum(int(r.get("mesh_peers", 0)) for r in rows) / len(rows)
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║         Aegis Shield — {hours}h Traffic Summary                   ║
╠══════════════════════════════════════════════════════════════╣
║  Total Requests:  {total_requests:<8}  Blocks: {total_blocks:<8}          ║
║  Redactions:      {total_redactions:<8}  Samples: {len(rows):<8}          ║
║  VPN Uptime:      {vpn_uptime}/{len(rows)} snapshots ({vpn_uptime*100//max(len(rows),1)}%)              ║
║  Avg Mesh Peers:  {mesh_avg:.1f}                                        ║
╚══════════════════════════════════════════════════════════════╝
""")


# ─── CLI ───────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print_status()
        return
    
    cmd = sys.argv[1].lower()
    
    if cmd == "status":
        print_status()
    
    elif cmd == "watch":
        print("Live traffic monitor — Ctrl+C to stop\n")
        try:
            while True:
                subprocess.run(["clear"], capture_output=True)
                print_status()
                time.sleep(5)
        except KeyboardInterrupt:
            print("\nStopped.")
    
    elif cmd == "history":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        print_history(hours)
    
    elif cmd == "spikes":
        spikes = detect_spikes()
        if spikes:
            print(f"\nTraffic spikes detected (last 24h):")
            for s in spikes:
                bar = "█" * min(int(s["ratio"]), 20)
                print(f"  {s['time'][:16]} | {s['requests']:3d} req | {bar} {s['ratio']}x")
        else:
            print("No traffic spikes detected.")
    
    elif cmd == "query":
        # Agentic query mode — output JSON for LLM consumption
        vpn = get_vpn_status()
        mesh = get_mesh_status()
        aegis = get_aegis_status()
        spikes = detect_spikes()
        history = load_history(24)
        
        query_result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "vpn": vpn,
            "mesh": mesh,
            "aegis": aegis,
            "recent_spikes": spikes[-5:],
            "history_samples": len(history),
            "total_requests_24h": sum(int(r.get("recent_requests", 0)) for r in history),
            "total_blocks_24h": sum(int(r.get("blocks", 0)) for r in history),
            "total_redactions_24h": sum(int(r.get("redactions", 0)) for r in history),
            "vpn_uptime_pct": round(
                sum(int(r.get("vpn_connected", 0)) for r in history) * 100 / max(len(history), 1), 1
            ) if history else 0,
        }
        
        print(json.dumps(query_result, indent=2))
    
    else:
        print(f"Usage: traffic_monitor.py [status|watch|history|spikes|query]")


if __name__ == "__main__":
    main()
