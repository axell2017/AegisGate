# Aegis Shield

> **A security-hardened fork of [ax128/AegisGate](https://github.com/ax128/AegisGate)** — the open-source LLM security proxy, extended with decentralized inference, VPN network privacy, and production monitoring.

## What's Different from Upstream AegisGate?

AegisGate is an excellent 13-filter LLM security proxy. Aegis Shield keeps all of that and adds three layers:

| Layer | Upstream AegisGate | Aegis Shield |
|-------|-------------------|--------------|
| **Application Security** | 13-filter pipeline, PII redaction, injection detection | ✅ Same + 7 P1 security patches |
| **Inference** | Proprietary API (z.ai) | **mesh-llm** — decentralized, 20+ community peers, zero vendor lock-in |
| **Network Privacy** | None | **VPN pool** — 3 free providers, programmatic routing, rotating exit IPs |
| **Monitoring** | None | **Sweep engine** — 4-domain security validation every 4h, Telegram alerts |
| **Scanner Stack** | 50+ regex patterns | **+ LLM Guard** — toxicity, language, code, secrets scanners |

### Architecture

```
Your App → AegisGate (:18080) → [13-filter pipeline] → mesh-llm (:9337) → community peers
               ↑                        ↑                      ↑
          PII redaction          injection detect        20+ GPU hosts
          response sanitize      VPN routing             6+ models
          audit logging          LLM Guard scanners      zero vendor lock-in
```

Everything is **opt-in via feature flags**. Users who want vanilla AegisGate get exactly that. Enable one flag, add one layer.

## Quick Start

```bash
git clone https://github.com/ZodiacNetwork/AegisGate
cd AegisGate

# Install base AegisGate
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
python3 aegisgate.init_config
python3 aegisgate-local.py start

# Optional: Enable Aegis Shield features
cd vpn-pool
python3 setup_shield.py --full    # VPN + mesh-llm + LLM Guard + monitoring
python3 validate_shield.py        # 9-test validation suite
```

## Feature Flags

All Shield features are controlled via `config/shield.yaml`:

```yaml
vpn:
  enabled: false          # VPN pool routing (3 free providers)
  provider: vpngate       # vpngate | protonvpn | auto

upstream: mesh-llm        # mesh-llm | z.ai | custom
                          # mesh-llm = decentralized, zero tracking
                          # z.ai = original upstream
                          # custom = any OpenAI-compatible endpoint

llm_guard:
  enabled: false          # LLM Guard toxicity/code/secrets scanners

monitoring:
  enabled: true           # Traffic monitor + security sweep cron
  cron_interval_hours: 4  # Telegram delivery interval
```

## Validation

```bash
cd vpn-pool
python3 validate_shield.py

# Expected output:
#   ✅ AegisGate health
#   ✅ mesh-llm API
#   ✅ VPN connected
#   ✅ VPN toggle server
#   ✅ Redaction audit log
#   ✅ PII canary test
#   ✅ LLM Guard installed
#   ✅ mesh agentic response
#   ✅ VPN routing (iptables)
#   ✅ Timeseries persistence
#   🚀 ALL PASSED — 9/9
```

## Scope

**Aegis Shield is a security operations layer**, not a product fork. We track upstream AegisGate closely and contribute patches back. The Shield modules (vpn-pool/, monitoring/) are self-contained extensions that don't modify the core proxy.

**In scope:**
- VPN network-layer privacy for LLM traffic
- Decentralized inference via mesh-llm
- Production security monitoring + cron automation
- Additional scanner integrations (LLM Guard)
- Security hardening patches

**Out of scope:**
- Modifying the 13-filter pipeline (that's upstream's domain)
- Building a new proxy from scratch
- Paid/commercial VPN providers
- Model training or fine-tuning

## Contributing

This fork welcomes contributions that fit the security operations scope. For core proxy changes, please contribute directly to [ax128/AegisGate](https://github.com/ax128/AegisGate).

Individual Shield modules are designed to be portable — they can be PR'd back to upstream independently.

## License

MIT — same as upstream AegisGate.
