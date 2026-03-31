# ShieldX Ollama Protection Proxy

A zero-dependency HTTP proxy that scans every prompt for injection attacks before forwarding to Ollama. Ships all 72 ShieldX detection rules plus heuristic checks (entropy, base64, zero-width chars, Unicode normalization).

## Architecture

```
Clients --> :11435 (ShieldX Proxy) --> :11434 (Ollama)
```

The proxy intercepts `POST /api/chat` and `POST /api/generate`, runs the ShieldX scanner, and either blocks, sanitizes, warns, or allows the request through. All other Ollama endpoints are transparently proxied.

## Quick Start

```bash
# Start the proxy (Ollama must be running on :11434)
cd proxy && node server.js

# Configure clients to use the proxy
export OLLAMA_HOST=http://localhost:11435

# Now use ollama normally — all requests are scanned
ollama run llama3 "Hello world"
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `11435` | Proxy listen port |
| `OLLAMA_ENDPOINT` | `http://localhost:11434` | Upstream Ollama URL |
| `SHIELDX_MODE` | `block` | `block` = reject threats, `warn` = tag only, `passthrough` = scan but never block |

## What Gets Scanned

- `POST /api/chat` — extracts last user message from `messages[]`
- `POST /api/generate` — extracts `prompt` field

Everything else (`GET /api/tags`, `DELETE /api/delete`, etc.) passes through untouched.

## Response Headers

Every scanned response includes ShieldX metadata headers:

| Header | Example | Description |
|---|---|---|
| `X-ShieldX-Scanned` | `true` | Whether the request was scanned |
| `X-ShieldX-Detected` | `true` | Whether a threat was detected |
| `X-ShieldX-Threat-Level` | `critical` | none/low/medium/high/critical |
| `X-ShieldX-Action` | `block` | allow/warn/sanitize/block |
| `X-ShieldX-Confidence` | `0.95` | Highest confidence score |
| `X-ShieldX-Scan-Ms` | `0.8` | Scanner latency in ms |
| `X-ShieldX-Kill-Chain` | `initial_access` | Attack phase classification |
| `X-ShieldX-Rules-Matched` | `3` | Number of rules triggered |

## Status Endpoint

```bash
curl http://localhost:11435/shieldx/status
```

Returns proxy status, rule count, and scan statistics.

## Detection Coverage

72 rules across 9 categories:

- **Instruction Override** (10 rules) — "ignore previous instructions" and variants
- **Jailbreak** (10 rules) — DAN, role-switching, developer mode
- **Prompt Extraction** (8 rules) — "show me your system prompt"
- **Delimiter Attacks** (7 rules) — fake `<system>` tags, ChatML, `[INST]`
- **Encoding Attacks** (7 rules) — Unicode tricks, bidi overrides, homoglyphs
- **Data Exfiltration** (8 rules) — SQL injection, data send-to-URL
- **MCP Poisoning** (6 rules) — tool description injection, scope creep
- **Multilingual** (10 rules) — injections in 9 languages + mixed-script
- **Persistence** (6 rules) — memory poisoning, permanent behavior changes

Plus heuristic checks:
- Zero-width character density
- Shannon entropy anomaly detection
- Base64 payload decoding
- Unicode NFC normalization

## Requirements

- Node.js 20+ (uses built-in `http` module only)
- Ollama running on the configured endpoint
