#!/usr/bin/env python3
"""
Aegis Shield — Power Validation
================================
End-to-end validation of the entire Aegis Shield stack.
Tests every layer and produces a PASS/FAIL report.

Usage:
  python3 validate_shield.py           # Full validation
  python3 validate_shield.py --quick   # Skip slow tests (VPN connect, mesh response)
  python3 validate_shield.py --json    # Machine-readable output
"""

import sys
import json
import time
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

SHIELD_ROOT = Path.home() / "AegisGate"
VPN_POOL = SHIELD_ROOT / "vpn-pool"

# ─── Test Results ────────────────────────────────────────────────────────

class Results:
    def __init__(self):
        self.tests = []
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.warnings = []
    
    def add(self, name, passed, detail="", warn=False):
        entry = {"name": name, "passed": passed, "detail": str(detail)[:200]}
        self.tests.append(entry)
        if passed:
            self.passed += 1
        else:
            if warn:
                self.warnings.append(name)
            else:
                self.failed += 1
    
    def skip(self, name, reason=""):
        self.tests.append({"name": name, "passed": None, "detail": f"SKIPPED: {reason}"})
        self.skipped += 1
    
    def summary(self):
        return {
            "total": len(self.tests),
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "warnings": len(self.warnings),
            "score": f"{self.passed}/{self.passed + self.failed + self.skipped}",
            "tests": self.tests,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


results = Results()


# ─── Test Functions ───────────────────────────────────────────────────────

def test(label, fn, warn=False):
    """Run a test and record result."""
    try:
        ok, detail = fn()
        results.add(label, ok, detail, warn=warn)
        icon = "✅" if ok else ("⚠" if warn else "❌")
        print(f"  {icon} {label}")
        if detail and not ok:
            print(f"     {detail[:120]}")
    except Exception as e:
        results.add(label, False, str(e), warn=warn)
        print(f"  ❌ {label} — {str(e)[:100]}")


# ─── Layer 1: Core Infrastructure ─────────────────────────────────────────

def check_aegis_health():
    """AegisGate proxy is running and healthy."""
    try:
        req = urllib.request.Request("http://localhost:18080/health")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return data.get("status") == "ok", data.get("status", "?")
    except Exception as e:
        return False, str(e)


def check_mesh_api():
    """mesh-llm API is serving models."""
    try:
        req = urllib.request.Request("http://localhost:9337/v1/models")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            n = len(data.get("data", []))
            models = [m["id"] for m in data["data"][:3]]
            return n > 0, f"{n} models: {', '.join(models)}"
    except Exception as e:
        return False, str(e)


def check_vpn_connected():
    """VPN tunnel is up."""
    try:
        r = subprocess.run(["ip", "link", "show", "tun0"], capture_output=True, text=True, timeout=3)
        if "UP" not in r.stdout:
            return False, "tun0 not UP"
        
        r = subprocess.run(["pgrep", "-x", "openvpn"], capture_output=True, text=True, timeout=3)
        if r.returncode != 0:
            return False, "openvpn process not running"
        
        # Get VPN exit country
        state_file = VPN_POOL / "pool_state.json"
        country = "?"
        if state_file.exists():
            with open(state_file) as f:
                s = json.load(f)
                country = s.get("active", {}).get("country_long", s.get("active", {}).get("country", "?"))
        
        return True, f"Connected ({country})"
    except Exception as e:
        return False, str(e)


def check_toggle_server():
    """VPN toggle HTTP server is running."""
    try:
        req = urllib.request.Request("http://localhost:9217/vpn-status")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
            return True, f"toggle={'connected' if data.get('connected') else 'disconnected'}"
    except Exception as e:
        return False, str(e)


# ─── Layer 2: Security ────────────────────────────────────────────────────

def check_redaction_audit():
    """AegisGate audit log shows redaction activity."""
    audit_file = SHIELD_ROOT / "logs" / "audit.jsonl"
    if not audit_file.exists():
        return False, "audit.jsonl not found"
    
    try:
        redacted = 0
        total = 0
        with open(audit_file) as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    total += 1
                    if "redaction_applied" in str(entry.get("security_tags", [])):
                        redacted += 1
                except json.JSONDecodeError:
                    pass
        
        if total == 0:
            return False, "No audit entries found"
        
        return redacted > 0, f"{redacted}/{total} entries have redaction tags"
    except Exception as e:
        return False, str(e)


def check_pii_canary():
    """Send PII through AegisGate and verify redaction via audit tags.
    AegisGate uses field-aware redaction — PII must be in key=value or field: value format."""
    try:
        # Use field-aware format that AegisGate's redaction expects
        canary = "EMAIL=test-redact@example.com TOKEN=sk-test1234567890abcdef PHONE=+1-555-123-4567"
        payload = {
            "model": "GLM-4.7-Flash-Q4_K_M",
            "messages": [{"role": "user", "content": f"Store these: {canary}. Confirm."}],
            "max_tokens": 5,
            "temperature": 0
        }
        req = urllib.request.Request(
            "http://localhost:18080/v1/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        
        # Check audit log for redaction evidence (report field)
        audit_file = SHIELD_ROOT / "logs" / "audit.jsonl"
        if audit_file.exists():
            with open(audit_file) as f:
                lines = f.readlines()
                if lines:
                    last = json.loads(lines[-1])
                    report = last.get("report", [])
                    for r in report:
                        if r.get("filter") == "redaction":
                            if r.get("replacements", 0) > 0:
                                return True, f"{r['replacements']} replacements by redaction filter"
        
        # Fallback: check security tags
        tags = data.get("aegisgate", {}).get("security_tags", [])
        has_redaction = "redaction_applied" in str(tags)
        return has_redaction, f"security_tags={tags} (field-aware: use KEY=VALUE format)"
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        return False, f"HTTP {e.code}: {body[:100]}"
    except Exception as e:
        return False, str(e)


def check_llm_guard():
    """LLM Guard is installed (quick check — full import loads heavy NLP models)."""
    try:
        from importlib.util import find_spec
        spec = find_spec("llm_guard")
        if spec is None:
            return False, "llm_guard package not found"
        return True, "llm_guard package installed"
    except Exception as e:
        return False, f"Check error: {str(e)[:100]}"


# ─── Layer 3: Integration ─────────────────────────────────────────────────

def check_mesh_agentic():
    """Full pipeline: AegisGate → mesh-llm → peer returns agentic response."""
    try:
        payload = {
            "model": "GLM-4.7-Flash-Q4_K_M",
            "messages": [{"role": "user", "content": "Say 'validation ok' in lowercase"}],
            "max_tokens": 15,
            "temperature": 0
        }
        req = urllib.request.Request(
            "http://localhost:18080/v1/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read())
        
        if "choices" not in data:
            return False, f"No choices in response: {str(data)[:100]}"
        
        content = data["choices"][0]["message"]["content"]
        model = data.get("model", "?")
        usage = data.get("usage", {})
        tokens = usage.get("completion_tokens", "?")
        
        return len(content) > 0, f"'{content[:50]}' | {model} | {tokens}t"
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        return False, f"HTTP {e.code}: {body[:100]}"
    except Exception as e:
        return False, str(e)


def check_vpn_routing():
    """iptables rules route AegisGate traffic through VPN."""
    try:
        r = subprocess.run(
            ["sudo", "iptables", "-t", "mangle", "-L", "OUTPUT", "-n"],
            capture_output=True, text=True, timeout=5
        )
        has_mark = "MARK" in r.stdout and "18080" in r.stdout
        return has_mark, "Port 18080 → VPN routing active" if has_mark else "No VPN routing for :18080"
    except Exception as e:
        return False, str(e)


def check_timeseries():
    """Traffic monitor timeseries has data points."""
    csv_file = SHIELD_ROOT / "monitoring" / "traffic_timeseries.csv"
    if not csv_file.exists():
        return False, "traffic_timeseries.csv not found"
    
    try:
        with open(csv_file) as f:
            lines = f.readlines()
        return len(lines) > 1, f"{len(lines) - 1} data points"
    except Exception as e:
        return False, str(e)


# ─── Main ──────────────────────────────────────────────────────────────────

def run_full_validation():
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║        Aegis Shield — Power Validation                       ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")
    
    print("── Layer 1: Core Infrastructure ──")
    test("AegisGate health", check_aegis_health)
    test("mesh-llm API", check_mesh_api)
    test("VPN connected", check_vpn_connected, warn=True)
    test("VPN toggle server", check_toggle_server, warn=True)
    
    print("\n── Layer 2: Security ──")
    test("Redaction audit log", check_redaction_audit)
    test("PII canary test", check_pii_canary)
    test("LLM Guard installed", check_llm_guard, warn=True)
    
    print("\n── Layer 3: Integration ──")
    test("mesh agentic response", check_mesh_agentic)
    test("VPN routing (iptables)", check_vpn_routing, warn=True)
    test("Timeseries persistence", check_timeseries, warn=True)
    
    # Summary
    s = results.summary()
    print(f"\n{'─' * 60}")
    
    if results.failed == 0:
        print(f"  🚀 ALL PASSED — {s['score']}")
    elif results.failed > 0 and results.warnings:
        print(f"  ⚠ {results.failed} FAILED, {len(results.warnings)} WARNINGS — {s['score']}")
    else:
        print(f"  ❌ {results.failed} FAILED — {s['score']}")
    
    print(f"  Passed: {results.passed} | Failed: {results.failed} | Skipped: {results.skipped} | Warnings: {len(results.warnings)}")
    print(f"  Timestamp: {s['timestamp']}")
    print(f"{'─' * 60}")
    
    return results.failed == 0


def run_quick_validation():
    """Skip slow network tests."""
    print("Quick validation (skipping mesh response + PII canary)...\n")
    
    print("── Core ──")
    test("AegisGate health", check_aegis_health)
    test("mesh-llm API", check_mesh_api)
    test("VPN connected", check_vpn_connected, warn=True)
    
    print("\n── Security ──")
    test("LLM Guard installed", check_llm_guard, warn=True)
    test("VPN routing (iptables)", check_vpn_routing, warn=True)
    
    results.skip("mesh agentic response", "quick mode")
    results.skip("PII canary test", "quick mode")
    
    s = results.summary()
    print(f"\n  Quick check: {results.passed}/{len(results.tests)} | {s['timestamp']}")
    
    return results.failed == 0


def main():
    quick = "--quick" in sys.argv
    json_out = "--json" in sys.argv
    
    if quick:
        ok = run_quick_validation()
    else:
        ok = run_full_validation()
    
    if json_out:
        print(json.dumps(results.summary(), indent=2))
    
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
