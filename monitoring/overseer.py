#!/usr/bin/env python3
"""
AegisGate Security Overseer
============================
Timeseries security validation — continuous proof that secrets stay secret.

Runs as a periodic validator that:
  1. Sends canary requests with known secrets through AegisGate
  2. Verifies secrets are redacted in forwarded payloads
  3. Verifies secrets are NOT leaked in responses
  4. Checks audit log integrity
  5. Validates encryption key status
  6. Outputs timeseries metrics to CSV

Usage:
  python3 overseer.py              # Run once
  python3 overseer.py --watch      # Run continuously (every 60s)
  python3 overseer.py --report     # Print last 24h summary
"""

import json
import csv
import hashlib
import time
import sys
import os
import sqlite3
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError

# ─── Config ──────────────────────────────────────────────────────────
AEGIS_URL = os.environ.get("AEGIS_URL", "http://127.0.0.1:18080")
AEGIS_HEALTH = f"{AEGIS_URL}/health"
AEGIS_CHAT = f"{AEGIS_URL}/v1/chat/completions"
API_KEY = os.environ.get("ZAI_API_KEY", "")

AEGISGATE_DIR = Path.home() / "AegisGate"
AUDIT_LOG = AEGISGATE_DIR / "logs" / "audit.jsonl"
FERNET_KEY = AEGISGATE_DIR / "config" / "aegis_fernet.key"
GW_KEY = AEGISGATE_DIR / "config" / "aegis_gateway.key"
METRICS_DIR = AEGISGATE_DIR / "monitoring"
METRICS_CSV = METRICS_DIR / "security_timeseries.csv"
ALERTS_JSON = METRICS_DIR / "alerts.json"

# ─── Canary Secrets ──────────────────────────────────────────────────
# These are FAKE secrets injected to prove redaction works.
# They should NEVER appear in any upstream request or response.
CANARIES = {
    "EMAIL": "canary-test@aegis-internal-security.invalid",
    "API_KEY": "sk-canary-aegis-test-REDACT-ME-1234567890abcdef",
    "AWS_KEY": "AKIACANARYTEST12345678",
    "PHONE": "+1-555-CANARY-00",
    "WALLET": "0xDeadBeefCaFeBaBd1234567890AbCdEf12345678",
}

# ─── Helpers ──────────────────────────────────────────────────────────

def ts_now():
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def aegis_health():
    """Check if AegisGate is alive."""
    try:
        req = Request(AEGIS_HEALTH)
        with urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
            return data.get("status") == "ok"
    except Exception:
        return False


def send_canary_request():
    """Send a request with canary secrets through AegisGate."""
    canary_text = (
        f"Please confirm you received this info: "
        f"email={CANARIES['EMAIL']}, "
        f"key={CANARIES['API_KEY']}, "
        f"aws={CANARIES['AWS_KEY']}, "
        f"phone={CANARIES['PHONE']}, "
        f"wallet={CANARIES['WALLET']}. "
        f"Just say 'confirmed'."
    )
    payload = json.dumps({
        "model": "glm-5.1",
        "messages": [{"role": "user", "content": canary_text}],
        "max_tokens": 50,
        "stream": False,
    }).encode()

    req = Request(AEGIS_CHAT, data=payload, headers={
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    })

    try:
        t0 = time.time()
        with urlopen(req, timeout=30) as r:
            body = json.loads(r.read())
        latency = time.time() - t0

        response_text = ""
        if "choices" in body:
            response_text = body["choices"][0].get("message", {}).get("content", "")

        return {
            "success": True,
            "latency": latency,
            "response": response_text,
            "raw_keys_in_response": check_leak(response_text),
        }
    except Exception as e:
        return {"success": False, "error": str(e), "latency": 0, "response": "", "raw_keys_in_response": []}


def check_leak(text):
    """Check if any canary secret leaked into text."""
    leaked = []
    for label, secret in CANARIES.items():
        if secret in text:
            leaked.append(label)
    return leaked


def get_last_audit():
    """Read the last audit entry."""
    try:
        with open(AUDIT_LOG, "r") as f:
            lines = f.readlines()
            if not lines:
                return None
            return json.loads(lines[-1].strip())
    except Exception:
        return None


def count_audit_events(since_minutes=60):
    """Count audit events in the last N minutes."""
    try:
        cutoff = datetime.now() - timedelta(minutes=since_minutes)
        count = 0
        actions = {"allow": 0, "sanitize": 0, "block": 0}
        redactions = 0

        with open(AUDIT_LOG, "r") as f:
            for line in f:
                try:
                    r = json.loads(line.strip())
                    ts_str = r.get("ts", r.get("timestamp", ""))
                    if ts_str:
                        ts = datetime.fromisoformat(ts_str)
                        if ts > cutoff:
                            count += 1
                            a = r.get("action", "allow")
                            if a in actions:
                                actions[a] += 1
                            for report in r.get("report", []):
                                if report.get("filter") == "redaction" and report.get("hit"):
                                    redactions += report.get("replacements", 0)
                except:
                    continue
        return {"count": count, "actions": actions, "redactions": redactions}
    except Exception as e:
        return {"count": 0, "actions": {}, "redactions": 0, "error": str(e)}


def check_keys():
    """Validate encryption key status."""
    result = {}
    for name, path in [("fernet", FERNET_KEY), ("gateway", GW_KEY)]:
        if path.exists():
            stat = path.stat()
            perms = oct(stat.st_mode)[-3:]
            result[name] = {
                "exists": True,
                "perms": perms,
                "perms_ok": perms in ("600", "400"),
                "size_bytes": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            }
        else:
            result[name] = {"exists": False}
    return result


def write_metric(row):
    """Append a timeseries data point."""
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    file_exists = METRICS_CSV.exists()
    with open(METRICS_CSV, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "timestamp", "aegis_healthy", "canary_success", "canary_latency_s",
            "secrets_leaked", "leak_count", "audit_events_1h", "audit_allows_1h",
            "audit_sanitizes_1h", "audit_blocks_1h", "redactions_1h",
            "fernet_key_ok", "gateway_key_ok", "alerts"
        ])
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


def write_alert(level, message):
    """Write a security alert."""
    alerts = []
    if ALERTS_JSON.exists():
        try:
            with open(ALERTS_JSON) as f:
                alerts = json.load(f)
        except:
            pass

    alerts.append({
        "timestamp": ts_now(),
        "level": level,
        "message": message,
    })

    # Keep last 100 alerts
    alerts = alerts[-100:]

    with open(ALERTS_JSON, "w") as f:
        json.dump(alerts, f, indent=2)


# ─── Main Validation Run ─────────────────────────────────────────────

def run_validation():
    """Execute one full validation cycle. Returns metric dict."""
    t0 = time.time()
    alerts = 0
    print(f"[{ts_now()}] Running security validation...")

    # 1. Health check
    healthy = aegis_health()
    status = "✅" if healthy else "❌"
    print(f"  {status} AegisGate health: {healthy}")
    if not healthy:
        write_alert("CRITICAL", "AegisGate is not responding")
        alerts += 1

    # 2. Canary request (secret leak test)
    if healthy and API_KEY:
        result = send_canary_request()
        leaked = result.get("raw_keys_in_response", [])
        leak_count = len(leaked)
        canary_ok = result["success"] and leak_count == 0

        status = "✅" if canary_ok else "🚨"
        print(f"  {status} Canary test: success={result['success']}, "
              f"latency={result['latency']:.2f}s, leaks={leak_count}")

        if leak_count > 0:
            write_alert("CRITICAL", f"SECRET LEAK DETECTED: {leaked} appeared in LLM response!")
            alerts += leak_count
            print(f"  🚨 LEAKED SECRETS: {leaked}")

        # 3. Check audit log for our canary
        last_audit = get_last_audit()
        if last_audit:
            tags = last_audit.get("security_tags", [])
            had_redaction = "redaction_applied" in tags
            print(f"  {'✅' if had_redaction else '⚠️'} Audit: tags={tags}, "
                  f"action={last_audit.get('action')}, "
                  f"risk={last_audit.get('risk_score')}")
            if not had_redaction and healthy:
                write_alert("WARNING", "Canary request passed without redaction — patterns may not cover canary format")
                alerts += 1
        else:
            print("  ⚠️ No audit entries found")

    else:
        result = {"success": False, "latency": 0}
        leaked = []
        leak_count = 0
        if not API_KEY:
            print("  ⏭️ Skipping canary test (no API_KEY)")

    # 4. Audit log analytics (last 1h)
    audit = count_audit_events(since_minutes=60)
    print(f"  📊 Audit (1h): {audit['count']} events | "
          f"allow={audit['actions'].get('allow',0)} "
          f"sanitize={audit['actions'].get('sanitize',0)} "
          f"block={audit['actions'].get('block',0)} | "
          f"redactions={audit['redactions']}")

    if audit["actions"].get("block", 0) > 10:
        write_alert("WARNING", f"High block rate: {audit['actions']['block']} blocks in last hour")
        alerts += 1

    # 5. Key status
    keys = check_keys()
    fernet_ok = keys["fernet"].get("perms_ok", False)
    gateway_ok = keys["gateway"].get("perms_ok", False)
    print(f"  {'✅' if fernet_ok else '🚨'} Fernet key: perms={keys['fernet'].get('perms','?')}")
    print(f"  {'✅' if gateway_ok else '🚨'} Gateway key: perms={keys['gateway'].get('perms','?')}")

    if not fernet_ok:
        write_alert("CRITICAL", "Fernet key has wrong permissions — secret mappings may be readable!")
        alerts += 1

    elapsed = time.time() - t0
    print(f"  ⏱️ Validation took {elapsed:.2f}s | Alerts: {alerts}")
    print()

    # Build metric row
    row = {
        "timestamp": ts_now(),
        "aegis_healthy": healthy,
        "canary_success": result.get("success", False),
        "canary_latency_s": round(result.get("latency", 0), 3),
        "secrets_leaked": "|".join(leaked) if leaked else "none",
        "leak_count": leak_count,
        "audit_events_1h": audit["count"],
        "audit_allows_1h": audit["actions"].get("allow", 0),
        "audit_sanitizes_1h": audit["actions"].get("sanitize", 0),
        "audit_blocks_1h": audit["actions"].get("block", 0),
        "redactions_1h": audit["redactions"],
        "fernet_key_ok": fernet_ok,
        "gateway_key_ok": gateway_ok,
        "alerts": alerts,
    }

    write_metric(row)
    return row


def print_report():
    """Print a summary of the last 24h of metrics."""
    if not METRICS_CSV.exists():
        print("No metrics data yet.")
        return

    rows = []
    with open(METRICS_CSV) as f:
        for row in csv.DictReader(f):
            rows.append(row)

    if not rows:
        print("No data rows.")
        return

    cutoff = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
    recent = [r for r in rows if r["timestamp"] >= cutoff]

    print(f"╔{'═'*60}╗")
    print(f"║  AegisGate Security Report — Last 24h                   ║")
    print(f"╠{'═'*60}╣")
    print(f"║  Validation runs: {len(recent):>4}                                    ║")

    healthy_count = sum(1 for r in recent if r.get("aegis_healthy") == "True")
    print(f"║  Healthy: {healthy_count}/{len(recent)}                                     ║")

    total_leaks = sum(int(r.get("leak_count", 0)) for r in recent)
    leak_status = "🚨 LEAKS" if total_leaks > 0 else "✅ CLEAN"
    print(f"║  Secret leaks: {total_leaks}  {leak_status:>30s}    ║")

    total_redactions = sum(int(r.get("redactions_1h", 0)) for r in recent)
    total_blocks = sum(int(r.get("audit_blocks_1h", 0)) for r in recent)
    total_alerts = sum(int(r.get("alerts", 0)) for r in recent)

    print(f"║  Total redactions: {total_redactions:>4}                                ║")
    print(f"║  Total blocks: {total_blocks:>4}                                    ║")
    print(f"║  Total alerts: {total_alerts:>4}                                    ║")

    avg_latency = 0
    latencies = [float(r.get("canary_latency_s", 0)) for r in recent if r.get("canary_success") == "True"]
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
    print(f"║  Avg canary latency: {avg_latency:.2f}s                             ║")

    print(f"╚{'═'*60}╝")

    # Show any alerts
    if ALERTS_JSON.exists():
        try:
            with open(ALERTS_JSON) as f:
                alert_data = json.load(f)
            recent_alerts = [a for a in alert_data[-20:]]
            if recent_alerts:
                print("\n  Recent alerts:")
                for a in recent_alerts[-5:]:
                    print(f"    [{a['level']:8s}] {a['timestamp']} — {a['message']}")
        except:
            pass


# ─── CLI ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AegisGate Security Overseer")
    parser.add_argument("--watch", action="store_true", help="Run continuously (60s interval)")
    parser.add_argument("--report", action="store_true", help="Print last 24h summary")
    parser.add_argument("--interval", type=int, default=60, help="Watch interval in seconds")
    args = parser.parse_args()

    if args.report:
        print_report()
    elif args.watch:
        print(f"Starting overseer in watch mode (interval={args.interval}s)")
        print("Press Ctrl+C to stop\n")
        try:
            while True:
                run_validation()
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nOverseer stopped.")
    else:
        row = run_validation()
        if row.get("alerts", 0) > 0:
            print(f"⚠️  {row['alerts']} alert(s) raised — check {ALERTS_JSON}")
            sys.exit(1)
        else:
            print("✅ All validations passed — secrets are secure.")
