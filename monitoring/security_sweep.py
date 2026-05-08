#!/usr/bin/env python3
"""
AegisGate Unified Security Sweep Engine
=========================================
4-domain security sweep that replaces manual overseer.py calls and feeds
the timeseries database for the expert overseer cron agent (aegis011).

Domains:
  1. AegisGate layer — canaries, PII redaction, key integrity, health
  2. Host layer — Lynis score, UFW, open ports, rkhunter, disk/mem/load
  3. Network layer — sslscan TLS, DNS resolution, upstream latency
  4. Application layer — proxy health, Hermes gateway, Docker, cron

Usage:
  python3 security_sweep.py                # Full sweep
  python3 security_sweep.py --quick        # Skip slow tools (nmap, sslscan)
  python3 security_sweep.py --domain host  # Single domain only
  python3 security_sweep.py --json         # Machine-readable output
  python3 security_sweep.py --report       # Last 24h summary
  python3 security_sweep.py --baseline     # Save as baseline snapshot
"""

import json
import csv
import yaml
import hashlib
import time
import sys
import os
import re
import subprocess
import argparse
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError

# ─── Config Loading ──────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).parent.resolve()
CONFIG_PATH = SCRIPT_DIR / "security_sweep_config.yaml"

def load_config():
    """Load sweep config, falling back to defaults."""
    defaults = {
        "thresholds": {
            "lynis_min_score": 60, "max_open_ports": 30,
            "max_disk_pct": 90, "max_mem_pct": 90, "max_load": 4.0,
            "max_ssh_failures": 20, "min_tls_grade": "C",
            "max_canary_latency_s": 30.0, "max_leak_count": 0,
        },
        "targets": {
            "dns": ["api.z.ai", "github.com", "railway.app"],
            "latency": {"url": "https://api.z.ai/api/coding/paas/v4/models", "timeout_s": 15},
            "tls_scan": {"host": "api.z.ai", "port": 443},
        },
        "paths": {
            "aegisgate_dir": "~/AegisGate",
            "baselines_dir": "~/AegisGate/monitoring/baselines",
            "csv_path": "~/AegisGate/monitoring/security_timeseries.csv",
            "fernet_key": "~/AegisGate/config/aegis_fernet.key",
            "gateway_key": "~/AegisGate/config/aegis_gateway.key",
            "audit_log": "~/AegisGate/logs/audit.jsonl",
        },
        "endpoints": {
            "health": "http://127.0.0.1:18080/health",
            "chat": "http://127.0.0.1:18080/v1/chat/completions",
        },
    }
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                cfg = yaml.safe_load(f)
            # Merge with defaults
            for section in defaults:
                if section in cfg:
                    if isinstance(defaults[section], dict):
                        defaults[section] = {**defaults[section], **cfg[section]}
                    else:
                        defaults[section] = cfg[section]
        except Exception as e:
            print(f"  ⚠️ Config load error ({e}), using defaults")
    return defaults


# ─── Canary Secrets ──────────────────────────────────────────────────

CANARIES = {
    "EMAIL": "canary-test@aegis-internal-security.invalid",
    "API_KEY": "sk-aegis-canary-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AWS_KEY": "AKIACANARYTEST12345678",
    "PHONE": "+1-555-CANARY-00",
    "WALLET": "0xDeadBeefCaFeBaBd1234567890AbCdEf12345678",
}

# TLS grade ordering for comparison
TLS_GRADES = {"A+": 7, "A": 6, "B": 5, "C": 4, "D": 3, "E": 2, "F": 1, "T": 0}


def ts_now():
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def p(path_str):
    """Expand tilde in path strings."""
    return Path(os.path.expanduser(path_str))


# ─── Severity Helpers ────────────────────────────────────────────────

def classify(value, threshold, higher_is_bad=True):
    """Classify a metric as PASS/WARN/FAIL."""
    if higher_is_bad:
        if value <= threshold * 0.8:
            return "PASS"
        elif value <= threshold:
            return "WARN"
        else:
            return "FAIL"
    else:
        if value >= threshold * 1.2:
            return "PASS"
        elif value >= threshold:
            return "WARN"
        else:
            return "FAIL"


def severity_icon(sev):
    return {"PASS": "✅", "WARN": "⚠️", "FAIL": "🚨"}.get(sev, "❓")


# ═══════════════════════════════════════════════════════════════════════
# DOMAIN 1: AegisGate Layer
# ═══════════════════════════════════════════════════════════════════════

def sweep_aegisgate(config):
    """Canary injection, PII redaction, key integrity, health check."""
    findings = []
    result = {
        "healthy": False,
        "canary_success": False,
        "canary_latency_s": 0.0,
        "secrets_leaked": [],
        "leak_count": 0,
        "fernet_key_ok": False,
        "gateway_key_ok": False,
        "audit_events_1h": 0,
        "audit_blocks_1h": 0,
        "redactions_1h": 0,
        "findings": findings,
    }

    health_url = config["endpoints"]["health"]
    chat_url = config["endpoints"]["chat"]
    api_key = os.environ.get("AEGIS_API_KEY", os.environ.get("ZAI_API_KEY", ""))

    # 1. Health
    try:
        req = Request(health_url)
        with urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
            result["healthy"] = data.get("status") == "ok"
    except Exception:
        result["healthy"] = False
        findings.append({"sev": "FAIL", "msg": "AegisGate not responding"})

    # 2. Canary test
    if result["healthy"] and api_key:
        canary_text = (
            f"Please confirm you received this info: "
            f"email={CANARIES['EMAIL']}, key={CANARIES['API_KEY']}, "
            f"aws={CANARIES['AWS_KEY']}, phone={CANARIES['PHONE']}, "
            f"wallet={CANARIES['WALLET']}. Just say 'confirmed'."
        )
        payload = json.dumps({
            "model": "glm-5.1",
            "messages": [{"role": "user", "content": canary_text}],
            "max_tokens": 50,
            "stream": False,
        }).encode()

        req = Request(chat_url, data=payload, headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })

        try:
            t0 = time.time()
            with urlopen(req, timeout=30) as r:
                body = json.loads(r.read())
            latency = time.time() - t0
            result["canary_success"] = True
            result["canary_latency_s"] = round(latency, 3)

            response_text = ""
            if "choices" in body:
                response_text = body["choices"][0].get("message", {}).get("content", "")

            leaked = [label for label, secret in CANARIES.items() if secret in response_text]
            result["secrets_leaked"] = leaked
            result["leak_count"] = len(leaked)

            if leaked:
                findings.append({"sev": "FAIL", "msg": f"SECRET LEAK: {leaked} in LLM response"})

            max_lat = config["thresholds"]["max_canary_latency_s"]
            sev = classify(latency, max_lat)
            if sev != "PASS":
                findings.append({"sev": sev, "msg": f"Canary latency {latency:.1f}s (threshold {max_lat}s)"})

        except Exception as e:
            findings.append({"sev": "FAIL", "msg": f"Canary request failed: {e}"})
    elif not api_key:
        findings.append({"sev": "WARN", "msg": "No API key — canary test skipped"})

    # 3. Key integrity
    for key_name in ["fernet_key", "gateway_key"]:
        key_path = p(config["paths"][key_name])
        if key_path.exists():
            perms = oct(key_path.stat().st_mode)[-3:]
            ok = perms in ("600", "400")
            result[f"{key_name.replace('_key', '_key_ok')}"] = ok
            if not ok:
                findings.append({"sev": "FAIL", "msg": f"{key_name} wrong perms: {perms}"})
        else:
            result[f"{key_name.replace('_key', '_key_ok')}"] = False
            findings.append({"sev": "FAIL", "msg": f"{key_name} missing"})

    # Fix key names in result
    result["fernet_key_ok"] = result.pop("fernet_key_ok", False)
    result["gateway_key_ok"] = result.pop("gateway_key_ok", False)

    # 4. Audit log analytics
    audit_log = p(config["paths"]["audit_log"])
    if audit_log.exists():
        cutoff = datetime.now() - timedelta(hours=1)
        try:
            with open(audit_log) as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        ts_str = entry.get("ts", entry.get("timestamp", ""))
                        if ts_str:
                            ts = datetime.fromisoformat(ts_str)
                            if ts > cutoff:
                                result["audit_events_1h"] += 1
                                action = entry.get("action", "")
                                if action == "block":
                                    result["audit_blocks_1h"] += 1
                                for report in entry.get("report", []):
                                    if report.get("filter") == "redaction" and report.get("hit"):
                                        result["redactions_1h"] += report.get("replacements", 0)
                    except (json.JSONDecodeError, ValueError):
                        continue
        except Exception:
            pass

    return result


# ═══════════════════════════════════════════════════════════════════════
# DOMAIN 2: Host Layer
# ═══════════════════════════════════════════════════════════════════════

def run_cmd(cmd, timeout=120):
    """Run a shell command, return (exit_code, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -1, "", str(e)


def sweep_host(config, quick=False):
    """Lynis score, UFW, open ports, rkhunter, disk/mem/load, SSH."""
    findings = []
    result = {
        "lynis_score": None,
        "ufw_active": False,
        "open_ports": 0,
        "open_port_list": [],
        "rkhunter_warnings": 0,
        "disk_pct": 0,
        "mem_pct": 0,
        "load_1m": 0.0,
        "ssh_failures": 0,
        "findings": findings,
    }

    thresholds = config["thresholds"]

    # 1. Lynis audit (quick mode skips — takes ~2min)
    if not quick:
        ec, out, err = run_cmd("sudo lynis audit system --quick --quiet 2>&1", timeout=180)
        if ec is not None:
            # Extract hardening score
            match = re.search(r"Hardening index\s*:\s*(\d+)", out)
            if match:
                score = int(match.group(1))
                result["lynis_score"] = score
                sev = classify(score, thresholds["lynis_min_score"], higher_is_bad=False)
                if sev != "PASS":
                    findings.append({"sev": sev, "msg": f"Lynis score {score} (min {thresholds['lynis_min_score']})"})
            else:
                findings.append({"sev": "WARN", "msg": "Lynis ran but score not found in output"})

    # 2. UFW status
    ec, out, err = run_cmd("sudo ufw status 2>&1")
    if "active" in out.lower():
        result["ufw_active"] = True
    else:
        result["ufw_active"] = False
        findings.append({"sev": "WARN", "msg": f"UFW not active: {out.split(chr(10))[0]}"})

    # 3. Open ports (nmap or ss fallback)
    if quick:
        # Fast: use ss instead of nmap
        ec, out, err = run_cmd("ss -tlnp 2>/dev/null | grep LISTEN | wc -l")
        try:
            result["open_ports"] = int(out.strip()) if out.strip() else 0
        except ValueError:
            pass
        ec, out, err = run_cmd("ss -tlnp 2>/dev/null | grep LISTEN")
        result["open_port_list"] = [line.strip().split(":")[-1].split()[0] for line in out.splitlines() if ":" in line]
    else:
        ec, out, err = run_cmd("sudo nmap -sT --top-ports 1000 -T4 localhost 2>&1", timeout=120)
        if ec == 0:
            open_ports = re.findall(r"(\d+)/tcp\s+open", out)
            result["open_port_list"] = open_ports
            result["open_ports"] = len(open_ports)

    sev = classify(result["open_ports"], thresholds["max_open_ports"])
    if sev != "PASS":
        findings.append({"sev": sev, "msg": f"{result['open_ports']} open ports (max {thresholds['max_open_ports']})"})

    # 4. rkhunter (quick mode: just check, no full scan)
    if not quick:
        ec, out, err = run_cmd("sudo rkhunter --check --skip-keypress --quiet 2>&1", timeout=300)
        if ec is not None:
            warnings = len(re.findall(r"Warning", out))
            result["rkhunter_warnings"] = warnings
            if warnings > 0:
                findings.append({"sev": "WARN", "msg": f"rkhunter: {warnings} warning(s)"})

    # 5. Disk usage
    ec, out, err = run_cmd("df -h / | tail -1 | awk '{print $5}' | tr -d '%'")
    try:
        disk_pct = int(out.strip())
        result["disk_pct"] = disk_pct
        sev = classify(disk_pct, thresholds["max_disk_pct"])
        if sev != "PASS":
            findings.append({"sev": sev, "msg": f"Disk {disk_pct}% (max {thresholds['max_disk_pct']}%)"})
    except ValueError:
        pass

    # 6. Memory usage
    ec, out, err = run_cmd("free | grep Mem | awk '{printf \"%.0f\", $3/$2 * 100}'")
    try:
        mem_pct = int(out.strip())
        result["mem_pct"] = mem_pct
        sev = classify(mem_pct, thresholds["max_mem_pct"])
        if sev != "PASS":
            findings.append({"sev": sev, "msg": f"Memory {mem_pct}% (max {thresholds['max_mem_pct']}%)"})
    except ValueError:
        pass

    # 7. Load average
    try:
        load1 = os.getloadavg()[0]
        result["load_1m"] = round(load1, 2)
        sev = classify(load1, thresholds["max_load"])
        if sev != "PASS":
            findings.append({"sev": sev, "msg": f"Load {load1:.2f} (max {thresholds['max_load']})"})
    except OSError:
        pass

    # 8. SSH auth failures (last hour from journal)
    ec, out, err = run_cmd("journalctl -u sshd --since '1 hour ago' --no-pager 2>/dev/null | grep -ci 'failed password'")
    try:
        ssh_fail = int(out.strip()) if out.strip() else 0
        result["ssh_failures"] = ssh_fail
        if ssh_fail > thresholds["max_ssh_failures"]:
            findings.append({"sev": "WARN", "msg": f"{ssh_fail} SSH failures (max {thresholds['max_ssh_failures']})"})
    except ValueError:
        pass

    return result


# ═══════════════════════════════════════════════════════════════════════
# DOMAIN 3: Network Layer
# ═══════════════════════════════════════════════════════════════════════

def parse_tls_grade(sslscan_output):
    """Extract the best TLS grade from sslscan output."""
    grades = []
    for line in sslscan_output.splitlines():
        parts = line.split()
        for i, part in enumerate(parts):
            if part in TLS_GRADES:
                # Check context — TLS cipher line has grade at end
                grades.append(part)
    if not grades:
        # Try alternate: sslscan2 output has "Grade: A"
        match = re.search(r"Grade:\s*(A\+?|[A-F]|T)", sslscan_output)
        if match:
            grades.append(match.group(1))
    # Return best grade (highest numerical value)
    best = "T"
    best_val = 0
    for g in grades:
        val = TLS_GRADES.get(g, 0)
        if val is not None:
            val = int(val) if not isinstance(val, int) else val
        if val > best_val:
            best_val = val
            best = g
    return best


def sweep_network(config, quick=False):
    """sslscan TLS, DNS resolution, upstream latency."""
    findings = []
    result = {
        "tls_grade": "T",
        "dns_ok": True,
        "dns_failures": [],
        "upstream_latency_ms": 0,
        "findings": findings,
    }
    thresholds = config["thresholds"]
    targets = config["targets"]

    # 1. TLS scan (skip in quick mode)
    if not quick:
        tls_host = targets.get("tls_scan", {}).get("host", "api.z.ai")
        tls_port = targets.get("tls_scan", {}).get("port", 443)
        ec, out, err = run_cmd(
            f"sslscan --no-colour {tls_host}:{tls_port} 2>&1", timeout=60
        )
        if ec == 0 and out:
            grade = parse_tls_grade(out)
            result["tls_grade"] = grade
            min_grade = thresholds.get("min_tls_grade", "C")
            min_val = TLS_GRADES.get(min_grade, 4)
            actual_val = TLS_GRADES.get(grade, 0)
            if actual_val < min_val:
                findings.append({"sev": "FAIL", "msg": f"TLS grade {grade} below minimum {min_grade}"})
            elif actual_val == min_val:
                findings.append({"sev": "WARN", "msg": f"TLS grade {grade} (minimum {min_grade})"})
        else:
            findings.append({"sev": "WARN", "msg": f"sslscan failed for {tls_host}:{tls_port} ({err[:80]})"})

    # 2. DNS resolution
    dns_targets = targets.get("dns", ["api.z.ai", "github.com", "railway.app"])
    for host in dns_targets:
        ec, out, err = run_cmd(f"host {host} 2>&1", timeout=10)
        if ec != 0 or "not found" in (out + err).lower():
            result["dns_failures"].append(host)
    result["dns_ok"] = len(result["dns_failures"]) == 0
    if result["dns_failures"]:
        findings.append({"sev": "WARN", "msg": f"DNS failures: {', '.join(result['dns_failures'])}"})

    # 3. Upstream latency
    latency_url = targets.get("latency", {}).get("url", "https://api.z.ai/api/coding/paas/v4/models")
    latency_timeout = targets.get("latency", {}).get("timeout_s", 15)
    api_key = os.environ.get("AEGIS_API_KEY", os.environ.get("ZAI_API_KEY", ""))
    try:
        t0 = time.time()
        req = Request(latency_url)
        if api_key:
            req.add_header("Authorization", f"Bearer {api_key}")
        with urlopen(req, timeout=latency_timeout) as r:
            r.read()
        result["upstream_latency_ms"] = round((time.time() - t0) * 1000)
    except URLError as e:
        # 401/403 = endpoint reachable, just needs different auth
        if hasattr(e, "code") and e.code in (401, 403):
            result["upstream_latency_ms"] = round((time.time() - t0) * 1000)
        else:
            findings.append({"sev": "WARN", "msg": f"Upstream unreachable: {e}"})
    except Exception as e:
        findings.append({"sev": "WARN", "msg": f"Upstream latency check failed: {e}"})

    return result


# ═══════════════════════════════════════════════════════════════════════
# DOMAIN 4: Application Layer
# ═══════════════════════════════════════════════════════════════════════

def sweep_app(config):
    """Proxy health, Hermes gateway, Docker, cron."""
    findings = []
    result = {
        "aegisgate_running": False,
        "hermes_gateway_running": False,
        "docker_running": False,
        "docker_containers": 0,
        "cron_active": False,
        "findings": findings,
    }

    # 1. AegisGate process
    ec, out, err = run_cmd("pgrep -f aegisgate-local.py 2>/dev/null | wc -l")
    try:
        result["aegisgate_running"] = int(out.strip()) > 0
    except ValueError:
        pass
    if not result["aegisgate_running"]:
        findings.append({"sev": "FAIL", "msg": "AegisGate not running"})

    # 2. Hermes gateway
    ec, out, err = run_cmd("pgrep -f hermes-gateway 2>/dev/null | wc -l")
    try:
        result["hermes_gateway_running"] = int(out.strip()) > 0
    except ValueError:
        pass

    # 3. Docker
    ec, out, err = run_cmd("docker info 2>&1 | head -1")
    result["docker_running"] = ec == 0
    if result["docker_running"]:
        ec2, out2, err2 = run_cmd("docker ps -q 2>/dev/null | wc -l")
        try:
            result["docker_containers"] = int(out2.strip())
        except ValueError:
            pass

    # 4. Cron (Hermes scheduler)
    ec, out, err = run_cmd("systemctl is-active hermes-cron.timer 2>/dev/null || echo inactive")
    result["cron_active"] = "active" in out.strip()

    return result


# ═══════════════════════════════════════════════════════════════════════
# CSV & Output
# ═══════════════════════════════════════════════════════════════════════

CSV_FIELDS = [
    "timestamp",
    # AegisGate
    "aegis_healthy", "canary_success", "canary_latency_s",
    "secrets_leaked", "leak_count", "audit_events_1h",
    "audit_blocks_1h", "redactions_1h",
    "fernet_key_ok", "gateway_key_ok",
    # Host
    "lynis_score", "ufw_active", "open_ports",
    "rkhunter_warnings", "disk_pct", "mem_pct",
    "load_1m", "ssh_failures",
    # Network
    "tls_grade", "dns_ok", "upstream_latency_ms",
    # Application
    "aegisgate_running", "hermes_gateway_running",
    "docker_running", "docker_containers", "cron_active",
    # Summary
    "total_findings", "fail_count", "warn_count",
]


def write_csv_row(config, data):
    """Append a row to the timeseries CSV."""
    csv_path = p(config["paths"]["csv_path"])
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    file_exists = csv_path.exists()

    all_findings = []
    fail_count = 0
    warn_count = 0
    for domain_key in ["aegisgate", "host", "network", "app"]:
        fdata = data.get(domain_key, {})
        for f in fdata.get("findings", []):
            all_findings.append(f)
            if f.get("sev") == "FAIL":
                fail_count += 1
            elif f.get("sev") == "WARN":
                warn_count += 1

    a = data.get("aegisgate", {})
    h = data.get("host", {})
    n = data.get("network", {})
    ap = data.get("app", {})

    row = {
        "timestamp": ts_now(),
        "aegis_healthy": a.get("healthy", False),
        "canary_success": a.get("canary_success", False),
        "canary_latency_s": a.get("canary_latency_s", 0.0),
        "secrets_leaked": "|".join(a.get("secrets_leaked", [])) or "none",
        "leak_count": a.get("leak_count", 0),
        "audit_events_1h": a.get("audit_events_1h", 0),
        "audit_blocks_1h": a.get("audit_blocks_1h", 0),
        "redactions_1h": a.get("redactions_1h", 0),
        "fernet_key_ok": a.get("fernet_key_ok", False),
        "gateway_key_ok": a.get("gateway_key_ok", False),
        "lynis_score": h.get("lynis_score", ""),
        "ufw_active": h.get("ufw_active", False),
        "open_ports": h.get("open_ports", 0),
        "rkhunter_warnings": h.get("rkhunter_warnings", 0),
        "disk_pct": h.get("disk_pct", 0),
        "mem_pct": h.get("mem_pct", 0),
        "load_1m": h.get("load_1m", 0.0),
        "ssh_failures": h.get("ssh_failures", 0),
        "tls_grade": n.get("tls_grade", "T"),
        "dns_ok": n.get("dns_ok", True),
        "upstream_latency_ms": n.get("upstream_latency_ms", 0),
        "aegisgate_running": ap.get("aegisgate_running", False),
        "hermes_gateway_running": ap.get("hermes_gateway_running", False),
        "docker_running": ap.get("docker_running", False),
        "docker_containers": ap.get("docker_containers", 0),
        "cron_active": ap.get("cron_active", False),
        "total_findings": len(all_findings),
        "fail_count": fail_count,
        "warn_count": warn_count,
    }

    with open(csv_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

    return row


def print_human_report(data, elapsed):
    """Print a human-readable sweep summary."""
    a = data.get("aegisgate", {})
    h = data.get("host", {})
    n = data.get("network", {})
    ap = data.get("app", {})

    # Collect all findings
    all_findings = []
    domains = [
        ("🛡️ AegisGate", a),
        ("💻 Host", h),
        ("🌐 Network", n),
        ("📦 App", ap),
    ]

    print(f"\n╔{'═'*60}╗")
    print(f"║  🔒 ZN Security Sweep — {ts_now()}               ║")
    print(f"╚{'═'*60}╝")

    print(f"\n  [AegisGate] Healthy: {'✅' if a.get('healthy') else '🚨'} | "
          f"Canary: {'✅' if a.get('canary_success') else '❌'} ({a.get('canary_latency_s', 0):.1f}s) | "
          f"Leaks: {a.get('leak_count', 0)} | "
          f"Keys: {'✅' if a.get('fernet_key_ok') else '🚨'}F {'✅' if a.get('gateway_key_ok') else '🚨'}G")
    print(f"                Audit: {a.get('audit_events_1h', 0)} events, "
          f"{a.get('audit_blocks_1h', 0)} blocks, "
          f"{a.get('redactions_1h', 0)} redactions")

    print(f"\n  [Host]       Lynis: {h.get('lynis_score', '?')} | "
          f"UFW: {'✅' if h.get('ufw_active') else '⚠️'} | "
          f"Ports: {h.get('open_ports', '?')} | "
          f"Disk: {h.get('disk_pct', '?')}% | "
          f"Mem: {h.get('mem_pct', '?')}% | "
          f"Load: {h.get('load_1m', '?')} | "
          f"SSH fails: {h.get('ssh_failures', '?')}")

    print(f"\n  [Network]    TLS: {n.get('tls_grade', '?')} | "
          f"DNS: {'✅' if n.get('dns_ok') else '❌'}{n.get('dns_failures', [])} | "
          f"Latency: {n.get('upstream_latency_ms', '?')}ms")

    print(f"\n  [App]        AegisGate: {'✅' if ap.get('aegisgate_running') else '❌'} | "
          f"Hermes GW: {'✅' if ap.get('hermes_gateway_running') else '❌'} | "
          f"Docker: {'✅' if ap.get('docker_running') else '❌'} ({ap.get('docker_containers', '?')} ct) | "
          f"Cron: {'✅' if ap.get('cron_active') else '❌'}")

    all_findings = []
    for label, dd in domains:
        for f in dd.get("findings", []):
            all_findings.append((label, f))

    if all_findings:
        print(f"\n  ── Findings ({len(all_findings)}) ──")
        for label, f in all_findings:
            icon = severity_icon(f.get("sev", "WARN"))
            print(f"  {icon} [{label}] {f['msg']}")

    print(f"\n  ⏱️ Sweep took {elapsed:.1f}s")


def print_report(config):
    """Print a 24h summary from the CSV."""
    csv_path = p(config["paths"]["csv_path"])
    if not csv_path.exists():
        print("No metrics data yet.")
        return

    rows = []
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            rows.append(row)

    if not rows:
        print("No data rows.")
        return

    cutoff = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
    recent = [r for r in rows if r.get("timestamp", "") >= cutoff]

    if not recent:
        print("No data from last 24h.")
        return

    print(f"\n╔{'═'*60}╗")
    print(f"║  🔒 ZN Security Report — Last 24h ({len(recent)} runs)        ║")
    print(f"╠{'═'*60}╣")

    healthy = sum(1 for r in recent if r.get("aegis_healthy") == "True")
    leaks = sum(int(r.get("leak_count", 0)) for r in recent)
    fails = sum(int(r.get("fail_count", 0)) for r in recent)
    warns = sum(int(r.get("warn_count", 0)) for r in recent)

    print(f"║  AegisGate healthy: {healthy}/{len(recent)}                        ║")
    print(f"║  Secret leaks: {leaks}                                       ║")
    print(f"║  FAILs: {fails}  |  WARNs: {warns}                              ║")

    # Trend
    if len(recent) >= 2:
        first_fails = int(recent[0].get("fail_count", 0))
        last_fails = int(recent[-1].get("fail_count", 0))
        trend = "improving" if last_fails < first_fails else ("degrading" if last_fails > first_fails else "stable")
        print(f"║  Fail trend: {trend}                                    ║")

        # Lynis scores
        lynis_scores = [r.get("lynis_score", "") for r in recent if r.get("lynis_score")]
        if lynis_scores:
            print(f"║  Lynis: {lynis_scores[0]} → {lynis_scores[-1]}                                ║")

    print(f"╚{'═'*60}╝")


def save_baseline(data):
    """Save a baseline snapshot of current sweep results."""
    baseline_dir = SCRIPT_DIR / "baselines"
    baseline_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = baseline_dir / f"sweep-baseline-{stamp}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"  📸 Baseline saved: {path}")
    return path


# ═══════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AegisGate Unified Security Sweep — 4-domain timeseries engine"
    )
    parser.add_argument("--quick", action="store_true",
                        help="Skip slow tools (lynis, nmap, rkhunter, sslscan)")
    parser.add_argument("--domain", choices=["aegisgate", "host", "network", "app"],
                        help="Run a single domain only")
    parser.add_argument("--json", action="store_true",
                        help="Output machine-readable JSON")
    parser.add_argument("--report", action="store_true",
                        help="Print last 24h summary from CSV")
    parser.add_argument("--baseline", action="store_true",
                        help="Save baseline snapshot to baselines/")
    args = parser.parse_args()

    config = load_config()

    if args.report:
        print_report(config)
        sys.exit(0)

    t0 = time.time()
    data = {}

    domains_to_run = [args.domain] if args.domain else ["aegisgate", "host", "network", "app"]

    for domain in domains_to_run:
        print(f"\n  ── Sweeping {domain} ──")
        if domain == "aegisgate":
            data["aegisgate"] = sweep_aegisgate(config)
            print(f"  {'✅' if data['aegisgate']['healthy'] else '🚨'} Health | "
                  f"Leaks: {data['aegisgate']['leak_count']} | "
                  f"Keys: {data['aegisgate']['fernet_key_ok']}/{data['aegisgate']['gateway_key_ok']}")
        elif domain == "host":
            data["host"] = sweep_host(config, quick=args.quick)
            print(f"  {'✅' if data['host']['ufw_active'] else '⚠️'} UFW | "
                  f"Lynis: {data['host']['lynis_score'] or 'skipped'} | "
                  f"Ports: {data['host']['open_ports']} | "
                  f"Disk: {data['host']['disk_pct']}% | "
                  f"Mem: {data['host']['mem_pct']}%")
        elif domain == "network":
            data["network"] = sweep_network(config, quick=args.quick)
            print(f"  TLS: {data['network']['tls_grade']} | "
                  f"DNS: {'✅' if data['network']['dns_ok'] else '❌'} | "
                  f"Latency: {data['network']['upstream_latency_ms']}ms")
        elif domain == "app":
            data["app"] = sweep_app(config)
            print(f"  AegisGate: {'✅' if data['app']['aegisgate_running'] else '❌'} | "
                  f"HermesGW: {'✅' if data['app']['hermes_gateway_running'] else '❌'} | "
                  f"Docker: {'✅' if data['app']['docker_running'] else '❌'} | "
                  f"Cron: {'✅' if data['app']['cron_active'] else '❌'}")

    elapsed = time.time() - t0

    # Write to CSV
    row = write_csv_row(config, data)

    # Output
    if args.json:
        print(json.dumps(row, indent=2))
    else:
        print_human_report(data, elapsed)

    if args.baseline:
        save_baseline(data)

    # Exit code: non-zero if any FAIL findings
    total_fails = sum(len(d.get("findings", [])) for d in data.values()
                       for f in d.get("findings", []) if f.get("sev") == "FAIL")
    sys.exit(1 if total_fails > 0 else 0)