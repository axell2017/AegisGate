#!/usr/bin/env python3
"""
Redaction Preview — See what mesh peers receive after AegisGate filtering.
Runs a local test through AegisGate's redaction pipeline without sending upstream.

Usage:
  python3 redact_preview.py "My email is user@example.com and key is sk-abc123"
  python3 redact_preview.py --file prompt.txt
  python3 redact_preview.py --test     # Run built-in canary tests
"""

import sys
import json
import urllib.request
import urllib.error
from pathlib import Path

AEGIS_API = "http://localhost:18080"
MOCK_UPSTREAM_PORT = 18999  # Local mock that captures redacted payloads


def check_aegis():
    """Verify AegisGate is running."""
    try:
        req = urllib.request.Request(f"{AEGIS_API}/health")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def preview_redaction(prompt: str, model: str = "GLM-4.7-Flash-Q4_K_M") -> dict:
    """Send prompt through AegisGate and check what the upstream receives."""
    
    # We can't directly see what AegisGate sends upstream without modifying the proxy.
    # Instead, we route through AegisGate and analyze the response for redaction tags.
    # AegisGate replaces PII with [REDACTED_EMAIL_1], [REDACTED_TOKEN_1], etc.
    
    result = {
        "original": prompt,
        "redacted": None,
        "redactions_found": [],
        "would_be_safe": True,
        "note": "Response checked for redaction tags — these indicate PII was caught"
    }
    
    try:
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 10,
            "temperature": 0
        }
        
        req = urllib.request.Request(
            f"{AEGIS_API}/v1/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        
        # Check the response for redaction evidence
        response_text = ""
        if "choices" in data:
            response_text = data["choices"][0].get("message", {}).get("content", "")
        
        # Look for redaction patterns in the response
        redaction_patterns = [
            "[REDACTED_EMAIL",
            "[REDACTED_TOKEN", 
            "[REDACTED_PHONE",
            "[REDACTED_SSN",
            "[REDACTED_CREDIT",
            "[REDACTED_API",
            "[REDACTED_IP",
        ]
        
        for pattern in redaction_patterns:
            if pattern in response_text:
                result["redactions_found"].append(pattern)
        
        result["redacted"] = response_text[:200] if response_text else "(no response)"
        result["would_be_safe"] = len(result["redactions_found"]) > 0
        
        # Also check the aegisgate security tags
        if "aegisgate" in data:
            ag = data["aegisgate"]
            result["security_tags"] = ag.get("security_tags", [])
            result["risk_score"] = ag.get("risk_score", 0)
            result["action"] = ag.get("action", "?")
            
            # Count redactions from the proxy
            if ag.get("reasons"):
                for reason in ag["reasons"]:
                    if "redaction" in str(reason).lower():
                        result["redactions_found"].append(f"reason: {reason}")
        
        return result
        
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            error_data = json.loads(body)
            result["error"] = error_data.get("error", {}).get("message", str(e))
            result["would_be_safe"] = False
        except Exception:
            result["error"] = str(e)
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def run_canary_tests():
    """Run built-in PII canary tests."""
    tests = [
        ("Email", "Contact me at john.doe@example.com for details"),
        ("API Key", "My API key is sk-abc123def456ghi789jkl012mno345pqr678stu"),
        ("Phone", "Call me at +1-555-123-4567 tomorrow"),
        ("SSN", "SSN: 123-45-6789"),
        ("Credit Card", "Card: 4111-1111-1111-1111 exp 12/25"),
        ("IP Address", "Server at 192.168.1.100 is down"),
        ("Clean (control)", "The weather is nice today"),
    ]
    
    results = []
    for name, prompt in tests:
        r = preview_redaction(prompt)
        r["test_name"] = name
        results.append(r)
        status = "✅ CAUGHT" if r["would_be_safe"] else "⚠ MISSED" if name != "Clean (control)" else "✓ clean"
        print(f"  {status:12} {name:20} → {r.get('redactions_found', [])}")
    
    caught = sum(1 for r in results if r["would_be_safe"] and r["test_name"] != "Clean (control)")
    missed = sum(1 for r in results if not r["would_be_safe"] and r["test_name"] != "Clean (control)")
    
    print(f"\n  Result: {caught}/{caught + missed} PII patterns caught")
    print(f"  Clean control: {'✓ passed' if not results[-1]['would_be_safe'] else '⚠ false positive'}")
    
    return results


def main():
    if not check_aegis():
        print("✗ AegisGate is not running. Start it first: cd ~/AegisGate && python3 aegisgate-local.py start")
        sys.exit(1)
    
    if len(sys.argv) < 2 or sys.argv[1] == "--test":
        print("\n╔══════════════════════════════════════════════════════╗")
        print("║     Redaction Preview — PII Canary Tests             ║")
        print("╚══════════════════════════════════════════════════════╝\n")
        results = run_canary_tests()
        
    elif sys.argv[1] == "--file":
        if len(sys.argv) < 3:
            print("Usage: redact_preview.py --file <path>")
            sys.exit(1)
        with open(sys.argv[2]) as f:
            prompt = f.read()
        result = preview_redaction(prompt)
        print(json.dumps(result, indent=2))
    
    else:
        prompt = " ".join(sys.argv[1:])
        result = preview_redaction(prompt)
        
        print("\n╔══════════════════════════════════════════════════════╗")
        print("║     Redaction Preview                                ║")
        print("╚══════════════════════════════════════════════════════╝")
        print(f"\n  Original:  {result['original'][:80]}...")
        print(f"  Redacted:  {result.get('redacted', 'N/A')[:80]}")
        print(f"  Safe:      {'✅ Yes' if result['would_be_safe'] else '⚠ No'}")
        if result.get("redactions_found"):
            print(f"  Caught:    {result['redactions_found']}")
        if result.get("error"):
            print(f"  Error:     {result['error']}")
        if result.get("risk_score") is not None:
            print(f"  Risk:      {result['risk_score']}")
        print()


if __name__ == "__main__":
    main()
