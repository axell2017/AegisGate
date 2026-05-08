# Aegis Shield — VPN Pool & Monitoring

Self-contained security operations layer for AegisGate. All modules are independent — each can be used standalone or together.

## Modules

| Module | File | Purpose |
|--------|------|---------|
| VPN Pool Manager | `vpn_pool.py` | Multi-provider VPN connections (VPN Gate, WireGuard) |
| VPN Routing | `vpn_route.py` | Policy-based traffic routing through VPN |
| VPN Kill-Switch | `vpn_toggle.py` | Quick VPN kill + reconnect + background watcher |
| VPN Toggle Server | `vpn_toggle_server.py` | HTTP API for toolbar integration (:9217) |
| Traffic Monitor | `traffic_monitor.py` | Live dashboard + timeseries persistence |
| Redaction Preview | `redact_preview.py` | See what mesh peers receive after PII filtering |
| LLM Guard Stack | `llm_guard_stack.py` | Toxicity/code/secrets scanners (requires `pip install llm-guard`) |
| Production Setup | `setup_shield.py` | One-command deployment with feature flags |
| Power Validation | `validate_shield.py` | 9-test end-to-end validation suite |

## Quick Start

```bash
# 1. Deploy everything
python3 setup_shield.py --full

# 2. Validate
python3 validate_shield.py

# 3. Monitor
python3 traffic_monitor.py status
python3 traffic_monitor.py watch    # Live 5s refresh
```

## VPN Pool

```bash
# Fetch server list from VPN Gate (6000+ volunteer servers)
python3 vpn_pool.py refresh

# List available servers (filtered by quality)
python3 vpn_pool.py list

# Auto-connect to best server
python3 vpn_pool.py auto

# Manual connect
python3 vpn_pool.py connect 5       # Connect to pool index 5
python3 vpn_pool.py connect vpngate_unknown_219-100-37-10  # By ID

# Cycle to next server
python3 vpn_pool.py cycle

# Status + health
python3 vpn_pool.py status
python3 vpn_pool.py health

# Disconnect
python3 vpn_pool.py disconnect
```

## VPN Routing

```bash
# Route AegisGate traffic through VPN
python3 vpn_route.py route 18080

# Route a named service
python3 vpn_route.py cover hermes   # Hermes ports
python3 vpn_route.py cover web      # Web browsing (80, 443)
python3 vpn_route.py cover all      # Everything (⚠ risky)

# Check status
python3 vpn_route.py status

# Remove all routing
python3 vpn_route.py reset
```

## Kill-Switch

```bash
# Kill VPN, restore normal internet
python3 vpn_toggle.py kill

# Status check
python3 vpn_toggle.py status

# Background watcher (notifications on VPN drop/restore)
python3 vpn_toggle.py watch

# Kill stale VPN + reconnect fresh
python3 vpn_toggle.py reconnect

# HTTP server for toolbar integration
python3 vpn_toggle_server.py        # Serves on :9217
```

## Traffic Monitor

```bash
python3 traffic_monitor.py status    # Current snapshot
python3 traffic_monitor.py watch     # Live 5s refresh
python3 traffic_monitor.py history   # 24h summary
python3 traffic_monitor.py spikes    # Detect traffic spikes
python3 traffic_monitor.py query     # JSON for agentic consumption
```

Data persists in `~/AegisGate/monitoring/traffic_timeseries.csv` across sessions.

## Redaction Testing

```bash
# Run PII canary tests through AegisGate
python3 redact_preview.py --test

# Preview a specific prompt
python3 redact_preview.py "My email is user@example.com"

# Note: AegisGate redacts in field-aware mode (KEY=VALUE format).
# Inline PII like "email me at x@y.com" may not be caught.
```

## LLM Guard

```bash
# Install (heavy NLP deps — may take a few minutes)
pip install llm-guard presidio-analyzer onnxruntime transformers

# Check status
python3 llm_guard_stack.py status

# Scan a prompt
python3 llm_guard_stack.py scan-input "I hate everyone"

# Run test suite
python3 llm_guard_stack.py test
```

## Configuration

All feature flags in `~/AegisGate/config/shield.yaml`:

```yaml
vpn:
  enabled: false
  provider: vpngate
upstream: mesh-llm
llm_guard:
  enabled: false
monitoring:
  enabled: true
  cron_interval_hours: 4
routing:
  ports_through_vpn: [18080]
```

## Pitfalls

- **OpenVPN daemon ≠ connection**: `--daemon` exits immediately but tun0 takes 5-15s. Always poll `ip link show tun0` for "UP".
- **TCP only**: UDP VPN Gate servers hang behind NAT. Always prefer TCP.
- **Field-aware redaction**: AegisGate catches `EMAIL=user@host.com` but not inline `email me at user@host.com`.
- **LLM Guard import is slow**: NLP models load on first use (10-30s). The validate script does a quick package check to avoid this.
- **VPN `cover all` is risky**: If the VPN drops with full routing, internet goes down. Use the kill-switch in Sonic List toolbar to recover.
