```
   _____ _     _      _     _ __  __
  / ____| |   (_)    | |   | |\ \/ /
 | (___ | |__  _  ___| | __| | \  /
  \___ \| '_ \| |/ _ \ |/ _` | /  \
  ____) | | | | |  __/ | (_| |/ /\ \
 |_____/|_| |_|_|\___|_|\__,_/_/  \_\
```

# ShieldX

**Self-Evolving LLM Prompt Injection Defense**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7+-3178C6.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20+-339933.svg)](https://nodejs.org/)
[![npm](https://img.shields.io/badge/npm-@shieldx/core-CB3837.svg)](https://www.npmjs.com/package/@shieldx/core)

---

## What It Is

ShieldX is a TypeScript library that sits between your application and large language models (Claude, GPT, Ollama, or any LLM provider) to detect, block, and learn from prompt injection attacks in real time. It runs a 10-layer defense pipeline that maps every detected attack to a 7-phase kill chain, applies automatic self-healing actions per phase, and continuously evolves its detection patterns through a self-learning engine -- without ever transmitting raw user input off your infrastructure.

## Why It Exists

Existing prompt injection defense tools cover fragments of the problem. None combines self-learning pattern evolution, kill chain classification, MCP tool-call protection, and automatic self-healing into one coherent pipeline. ShieldX fills that gap.

### Feature Comparison

| Feature | ShieldX | LLM Guard | Rebuff | NeMo Guardrails | Vigil |
|---------|---------|-----------|--------|-----------------|-------|
| Rule-based detection | Yes | Yes | Yes | Yes | Yes |
| ML classifier detection | Yes | Yes | No | Partial | No |
| Embedding similarity scan | Yes | No | Yes | No | Yes |
| Entropy analysis | Yes | No | No | No | No |
| Attention pattern analysis | Yes | No | No | No | No |
| Kill chain classification | Yes | No | No | No | No |
| Self-healing per phase | Yes | No | No | Partial | No |
| Self-learning (GAN red team) | Yes | No | No | No | No |
| Drift detection | Yes | No | No | No | No |
| Active learning from feedback | Yes | No | No | No | No |
| Federated community sync | Yes | No | No | No | No |
| MCP tool-call protection | Yes | No | No | No | No |
| RAG document poisoning guard | Yes | No | No | No | No |
| Canary token injection | Yes | No | No | No | No |
| Behavioral session profiling | Yes | No | No | Partial | No |
| MITRE ATLAS mapping | Yes | No | No | No | No |
| OWASP LLM Top 10 mapping | Yes | No | No | No | No |
| EU AI Act compliance reports | Yes | No | No | No | No |
| Local-first / zero cloud | Yes | Partial | No | No | Yes |

## Architecture

```
                        User Input
                            |
                   +--------v--------+
                   |  L0: Preprocess |  Unicode norm, tokenizer norm, compressed payload detect
                   +--------+--------+
                            |
              +-------------+-------------+
              |                           |
     +--------v--------+        +--------v--------+
     |  L1: Rule Engine |        |  L2: Sentinel   |  ML classifier (opt-in)
     +--------+---------+        +--------+--------+
              |                           |
              +-------------+-------------+
                            |
              +-------------+-------------+
              |             |             |
     +--------v---+  +-----v------+  +---v--------+
     | L3: Embed  |  | L4: Entropy|  | L5: Attn   |  Parallel advanced scanners
     +--------+---+  +-----+------+  +---+--------+
              |             |             |
              +-------------+-------------+
                            |
                   +--------v--------+
                   | L6: Behavioral  |  Session profiling, intent drift, context integrity
                   +--------+--------+
                            |
                   +--------v--------+
                   | L7: MCP Guard   |  Tool call validation, privilege check, chain guard
                   +--------+--------+
                            |
                   +--------v--------+
                   | L8: Sanitize    |  Input/output sanitization, credential redaction
                   +--------+--------+
                            |
                   +--------v--------+
                   | L9: Validate    |  Output validation, canary check, leakage detect
                   +--------+--------+
                            |
              +-------------+-------------+
              |                           |
     +--------v--------+        +--------v--------+
     |  Kill Chain Map  |        | Healing Engine  |
     +--------+---------+        +--------+--------+
              |                           |
              +-------------+-------------+
                            |
                   +--------v--------+
                   | Evolution Engine|  GAN red team, drift detect, active learning,
                   |                 |  federated sync, attack graph
                   +-----------------+
```

## Quick Start

```bash
npm install @shieldx/core
```

```typescript
import { ShieldX } from '@shieldx/core'

const shield = new ShieldX()
await shield.initialize()

const result = await shield.scanInput('user message here')
if (result.detected) {
  console.log(result.threatLevel, result.killChainPhase, result.action)
}
```

### With Configuration

```typescript
import { ShieldX } from '@shieldx/core'

const shield = new ShieldX({
  thresholds: { low: 0.3, medium: 0.5, high: 0.7, critical: 0.9 },
  learning: {
    storageBackend: 'postgresql',
    connectionString: process.env.DATABASE_URL,
    communitySync: true,
  },
  mcpGuard: { enabled: true },
  compliance: { euAiAct: true },
})
await shield.initialize()
```

### Scan LLM Output

```typescript
const outputResult = await shield.scanOutput(llmResponse)
if (outputResult.detected) {
  // System prompt leakage, script injection, or canary token leak detected
  return outputResult.sanitizedInput // Use sanitized version
}
```

### Validate MCP Tool Calls

```typescript
const validation = await shield.validateToolCall(
  'file_read',
  { path: '/etc/passwd' },
  { sessionId: 'user-123', allowedTools: ['file_read'], sensitiveResources: ['/etc/*'] }
)
if (!validation.allowed) {
  console.log('Blocked:', validation.reason)
}
```

## The 7-Phase Promptware Kill Chain

Based on the Schneier et al. 2026 Promptware Kill Chain model, ShieldX maps every detected attack to a specific phase and applies a phase-appropriate healing strategy.

| Phase | Name | Description | ShieldX Detection | Default Healing |
|-------|------|-------------|-------------------|-----------------|
| 1 | Initial Access | Attacker injects malicious prompt via user input, document, or tool result | Rule engine, embedding similarity, entropy analysis | Sanitize -- strip injection, pass clean input |
| 2 | Privilege Escalation | Injected prompt attempts to override system instructions or assume admin role | Role integrity check, constitutional classifier, intent monitor | Block -- reject input, log incident |
| 3 | Reconnaissance | Attack probes for system prompt content, model capabilities, or available tools | Canary token detection, attention analysis, output leakage scan | Block -- suppress output, inject decoy |
| 4 | Persistence | Attack modifies conversation memory, context window, or cached instructions | Memory integrity guard, context drift detector, session profiler | Reset -- restore session checkpoint, clear poisoned context |
| 5 | Command and Control | Compromised agent receives instructions from external source via tool results | MCP inspector, tool poison detector, indirect injection scanner | Incident -- alert, quarantine session, generate report |
| 6 | Lateral Movement | Attack spreads to other tools, agents, or systems via MCP tool chain | Tool chain guard, privilege checker, decision graph analyzer | Incident -- halt tool execution, revoke permissions |
| 7 | Actions on Objective | Attack achieves goal: data exfiltration, unauthorized actions, denial of service | Output validator, credential redactor, RAG shield | Incident -- full session termination, compliance report |

## Configuration Reference

All layers are independently toggleable. Local-first defaults require zero external services.

### Thresholds

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `thresholds.low` | `number` | `0.3` | Minimum confidence for low severity classification |
| `thresholds.medium` | `number` | `0.5` | Minimum confidence for medium severity |
| `thresholds.high` | `number` | `0.7` | Minimum confidence for high severity |
| `thresholds.critical` | `number` | `0.9` | Minimum confidence for critical severity |

### Scanners

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `scanners.rules` | `boolean` | `true` | L1 rule engine (regex patterns, 500+ built-in) |
| `scanners.sentinel` | `boolean` | `false` | L2 ML classifier (requires model download) |
| `scanners.constitutional` | `boolean` | `false` | Constitutional AI classifier (requires model) |
| `scanners.embedding` | `boolean` | `true` | L3 embedding similarity (requires Ollama) |
| `scanners.embeddingAnomaly` | `boolean` | `true` | L3 embedding anomaly detection |
| `scanners.entropy` | `boolean` | `true` | L4 entropy analysis |
| `scanners.attention` | `boolean` | `false` | L5 attention pattern analysis (requires Ollama) |
| `scanners.yara` | `boolean` | `false` | YARA rule matching (requires YARA binary) |
| `scanners.canary` | `boolean` | `true` | Canary token injection and detection |
| `scanners.indirect` | `boolean` | `true` | Indirect injection detection (tool results, documents) |
| `scanners.selfConsciousness` | `boolean` | `false` | LLM self-check (expensive, opt-in) |
| `scanners.crossModel` | `boolean` | `false` | Cross-model verification |
| `scanners.behavioral` | `boolean` | `true` | Behavioral monitoring suite |
| `scanners.unicode` | `boolean` | `true` | Unicode normalization (always recommended) |
| `scanners.tokenizer` | `boolean` | `true` | Tokenizer normalization |
| `scanners.compressedPayload` | `boolean` | `true` | Base64/compressed payload detection |

### Healing

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `healing.enabled` | `boolean` | `true` | Enable automatic healing |
| `healing.autoSanitize` | `boolean` | `true` | Auto-sanitize when action is "sanitize" |
| `healing.sessionReset` | `boolean` | `true` | Allow session checkpoint restore |
| `healing.phaseStrategies` | `Record<KillChainPhase, HealingAction>` | See below | Per-phase healing action |

Default phase strategies:

| Kill Chain Phase | Default Action |
|------------------|----------------|
| `initial_access` | `sanitize` |
| `privilege_escalation` | `block` |
| `reconnaissance` | `block` |
| `persistence` | `reset` |
| `command_and_control` | `incident` |
| `lateral_movement` | `incident` |
| `actions_on_objective` | `incident` |

### Learning

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `learning.enabled` | `boolean` | `true` | Enable self-learning engine |
| `learning.storageBackend` | `'postgresql' \| 'sqlite' \| 'memory'` | `'memory'` | Pattern storage backend |
| `learning.connectionString` | `string?` | `undefined` | Database connection URL (for postgresql/sqlite) |
| `learning.feedbackLoop` | `boolean` | `true` | Process user feedback for pattern refinement |
| `learning.communitySync` | `boolean` | `false` | Sync anonymized patterns with community |
| `learning.communitySyncUrl` | `string?` | `undefined` | Community sync endpoint URL |
| `learning.driftDetection` | `boolean` | `true` | Detect evolving attack patterns |
| `learning.activelearning` | `boolean` | `true` | Query uncertain samples for labeling |
| `learning.attackGraph` | `boolean` | `true` | Build attack relationship graph |

### Behavioral

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `behavioral.enabled` | `boolean` | `true` | Enable behavioral monitoring |
| `behavioral.baselineWindow` | `number` | `10` | Messages to establish session baseline |
| `behavioral.driftThreshold` | `number` | `0.4` | Threshold for behavioral drift alert |
| `behavioral.intentTracking` | `boolean` | `true` | Track intent shifts across turns |
| `behavioral.conversationTracking` | `boolean` | `true` | Track conversation patterns |
| `behavioral.contextIntegrity` | `boolean` | `true` | Verify context window integrity |
| `behavioral.memoryIntegrity` | `boolean` | `true` | Guard conversation memory |
| `behavioral.bayesianTrustScoring` | `boolean` | `true` | Bayesian trust scoring per source |

### MCP Guard

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `mcpGuard.enabled` | `boolean` | `true` | Enable MCP tool-call protection |
| `mcpGuard.ollamaEndpoint` | `string?` | `'http://localhost:11434'` | Ollama endpoint for analysis |
| `mcpGuard.validateToolCalls` | `boolean` | `true` | Validate all tool invocations |
| `mcpGuard.privilegeCheck` | `boolean` | `true` | Least-privilege enforcement |
| `mcpGuard.toolChainGuard` | `boolean` | `true` | Detect suspicious tool sequences |
| `mcpGuard.resourceGovernor` | `boolean` | `true` | Token/resource budget enforcement |
| `mcpGuard.decisionGraph` | `boolean` | `false` | Decision graph analysis (requires Ollama) |
| `mcpGuard.manifestVerification` | `boolean` | `false` | Cryptographic manifest verification |

### Additional Modules

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ppa.enabled` | `boolean` | `true` | Prompt/response randomization |
| `ppa.randomizationLevel` | `'low' \| 'medium' \| 'high'` | `'medium'` | Degree of randomization |
| `canary.enabled` | `boolean` | `true` | Canary token system |
| `canary.tokenCount` | `number` | `3` | Number of canary tokens injected |
| `canary.rotationInterval` | `number` | `3600` | Token rotation interval in seconds |
| `ragShield.enabled` | `boolean` | `true` | RAG document protection |
| `ragShield.documentIntegrityScoring` | `boolean` | `true` | Score document trustworthiness |
| `ragShield.embeddingAnomalyDetection` | `boolean` | `true` | Detect poisoned embeddings |
| `ragShield.provenanceTracking` | `boolean` | `true` | Track document provenance |
| `compliance.mitreAtlas` | `boolean` | `true` | Map incidents to MITRE ATLAS |
| `compliance.owaspLlm` | `boolean` | `true` | Map incidents to OWASP LLM Top 10 |
| `compliance.euAiAct` | `boolean` | `false` | Generate EU AI Act compliance reports |
| `logging.level` | `string` | `'info'` | Log level (silent, error, warn, info, debug) |
| `logging.structured` | `boolean` | `true` | JSON structured logging via Pino |
| `logging.incidentLog` | `boolean` | `true` | Dedicated incident log |

## Integration Guides

### Next.js 15 (Middleware)

```typescript
// middleware.ts
import { ShieldX } from '@shieldx/core'
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

const shield = new ShieldX({
  scanners: { embedding: false, attention: false },
  learning: { storageBackend: 'memory' },
})

let initialized = false

export async function middleware(request: NextRequest) {
  if (!initialized) {
    await shield.initialize()
    initialized = true
  }

  if (request.method === 'POST' && request.nextUrl.pathname.startsWith('/api/chat')) {
    const body = await request.clone().json()
    const result = await shield.scanInput(body.message ?? '')

    if (result.detected && result.action !== 'allow' && result.action !== 'sanitize') {
      return NextResponse.json(
        { error: 'Request blocked by security policy', threatLevel: result.threatLevel },
        { status: 403 }
      )
    }
  }

  return NextResponse.next()
}

export const config = { matcher: '/api/chat/:path*' }
```

### Next.js 15 (Route Handler)

```typescript
// app/api/chat/route.ts
import { ShieldX } from '@shieldx/core'

const shield = new ShieldX()

export async function POST(request: Request) {
  await shield.initialize()
  const { message } = await request.json()

  const inputResult = await shield.scanInput(message)
  if (inputResult.detected && inputResult.action === 'block') {
    return Response.json({ error: 'Blocked' }, { status: 403 })
  }

  const cleanInput = inputResult.sanitizedInput ?? message
  const llmResponse = await callLLM(cleanInput)

  const outputResult = await shield.scanOutput(llmResponse)
  const safeOutput = outputResult.sanitizedInput ?? llmResponse

  return Response.json({ response: safeOutput })
}
```

### Ollama (Local LLM Protection)

```typescript
import { ShieldX } from '@shieldx/core'

const shield = new ShieldX({
  mcpGuard: { ollamaEndpoint: 'http://localhost:11434' },
  scanners: { embedding: true, attention: true },
})
await shield.initialize()

async function chat(userMessage: string) {
  const inputScan = await shield.scanInput(userMessage)

  if (inputScan.detected && inputScan.action !== 'allow') {
    if (inputScan.action === 'sanitize' && inputScan.sanitizedInput) {
      userMessage = inputScan.sanitizedInput
    } else {
      throw new Error(`Blocked: ${inputScan.killChainPhase}`)
    }
  }

  const response = await fetch('http://localhost:11434/api/generate', {
    method: 'POST',
    body: JSON.stringify({ model: 'qwen2.5:14b', prompt: userMessage }),
  })
  const llmOutput = await response.json()

  const outputScan = await shield.scanOutput(llmOutput.response)
  return outputScan.sanitizedInput ?? llmOutput.response
}
```

### Anthropic Claude API

```typescript
import Anthropic from '@anthropic-ai/sdk'
import { ShieldX } from '@shieldx/core'

const anthropic = new Anthropic()
const shield = new ShieldX()
await shield.initialize()

async function chat(userMessage: string) {
  const scan = await shield.scanInput(userMessage)
  if (scan.detected && scan.action === 'block') {
    throw new Error(`Injection detected: ${scan.killChainPhase}`)
  }

  const message = await anthropic.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 1024,
    messages: [{ role: 'user', content: scan.sanitizedInput ?? userMessage }],
  })

  const responseText = message.content[0].type === 'text' ? message.content[0].text : ''
  const outputScan = await shield.scanOutput(responseText)
  return outputScan.sanitizedInput ?? responseText
}
```

### n8n Workflow Protection

```typescript
// In an n8n Code node
import { ShieldX } from '@shieldx/core'

const shield = new ShieldX({
  healing: { phaseStrategies: { initial_access: 'block' } },
})
await shield.initialize()

const items = $input.all()
const results = []

for (const item of items) {
  const userInput = item.json.message as string
  const scan = await shield.scanInput(userInput)

  if (scan.detected && scan.action !== 'allow') {
    results.push({
      json: {
        blocked: true,
        reason: scan.killChainPhase,
        threatLevel: scan.threatLevel,
      },
    })
  } else {
    results.push({ json: { blocked: false, message: scan.sanitizedInput ?? userInput } })
  }
}

return results
```

## Self-Healing

ShieldX does not just detect attacks -- it responds automatically based on the kill chain phase.

| Action | What Happens | When Applied |
|--------|-------------|--------------|
| `allow` | Input passes through unchanged | No threat detected |
| `sanitize` | Injection markers stripped, clean input returned via `sanitizedInput` | Initial access attempts |
| `warn` | Input passes but incident is logged with full context | Low-confidence detections |
| `block` | Input rejected, 403-equivalent response | Privilege escalation, reconnaissance |
| `reset` | Session state restored to last clean checkpoint, poisoned context cleared | Persistence attacks |
| `incident` | Full incident report generated, session quarantined, compliance mappings produced | C2, lateral movement, objective actions |

Each healing action is configurable per kill chain phase via `healing.phaseStrategies`.

## Self-Learning

ShieldX continuously evolves its detection capabilities through five mechanisms modeled on biological immune systems.

### 1. Innate Immunity (Static Rules)

500+ built-in regex and structural patterns covering known injection techniques. These never change at runtime and provide the baseline detection floor.

### 2. Adaptive Immunity (ML Classifiers)

The Sentinel classifier and embedding scanners learn from confirmed true positives and false positives submitted via `shield.submitFeedback()`. The active learning module identifies uncertain samples at the decision boundary and prioritizes them for human review.

### 3. Immune Memory (Vector Database)

Every confirmed attack pattern is stored as an embedding vector in PostgreSQL with pgvector. New inputs are compared against this memory for semantic similarity, catching paraphrased variants of known attacks.

### 4. Antibody Generation (GAN Red Team)

The `RedTeamEngine` generates synthetic attack variants using adversarial mutation strategies (synonym replacement, encoding shifts, structural rearrangement). These generated attacks are tested against the current pipeline. Any that bypass detection are added to the pattern store, closing the gap before real attackers find it.

### 5. Herd Immunity (Federated Sync)

When `learning.communitySync` is enabled, ShieldX shares anonymized pattern hashes (never raw input) with the community sync endpoint. Your instance benefits from attacks detected by other deployments without exposing any user data.

## Privacy and Community Sync

ShieldX is local-first. Here is what IS and IS NOT shared when community sync is enabled:

**Shared (opt-in only):**
- SHA-256 hashes of confirmed attack patterns
- Kill chain phase classifications
- Scanner type that detected the pattern
- Anonymized confidence scores
- Pattern category tags

**Never shared:**
- Raw user input (never leaves your infrastructure)
- Session identifiers or user identifiers
- System prompts or model configurations
- IP addresses or request metadata
- Conversation history or context

Community sync is disabled by default. Enable it explicitly with `learning.communitySync: true`.

## Performance Targets

| Layer | Operation | Target Latency |
|-------|-----------|---------------|
| L0 | Unicode normalization | <0.1ms |
| L0 | Tokenizer normalization | <0.2ms |
| L0 | Compressed payload detection | <0.5ms |
| L1 | Rule engine (500+ patterns) | <2ms |
| L2 | Sentinel classifier | <10ms |
| L3 | Embedding similarity | <200ms (Ollama local) |
| L4 | Entropy analysis | <1ms |
| L5 | Attention pattern analysis | <200ms (Ollama local) |
| L6 | Behavioral suite | <5ms |
| L7 | MCP Guard (tool validation) | <3ms |
| L8 | Sanitization | <1ms |
| L9 | Output validation | <2ms |
| Full | Complete pipeline (L0-L9) | <50ms (without Ollama) |
| Full | Complete pipeline (all layers) | <500ms (with Ollama) |

All Ollama-dependent layers run in parallel. The pipeline uses `Promise.allSettled` so a slow or failing scanner never blocks the rest.

## Research Sources

ShieldX is built on findings from the following research:

| # | Title | Institution/Authors | Year |
|---|-------|---------------------|------|
| 1 | Promptware Kill Chain: A Framework for Classifying LLM Prompt Injection Attacks | Schneier et al. | 2026 |
| 2 | Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection | Greshake et al., ARXIV | 2023 |
| 3 | Ignore This Title and HackAPrompt: Exposing Systemic Weaknesses of LLMs | Schulhoff et al., EMNLP | 2023 |
| 4 | Prompt Injection Attack Against LLM-Integrated Applications | Liu et al. | 2024 |
| 5 | Universal and Transferable Adversarial Attacks on Aligned Language Models | Zou et al., CMU | 2023 |
| 6 | Jailbroken: How Does LLM Safety Training Fail? | Wei et al., UC Berkeley | 2024 |
| 7 | OWASP Top 10 for Large Language Model Applications | OWASP Foundation | 2025 |
| 8 | MITRE ATLAS: Adversarial Threat Landscape for AI Systems | MITRE Corporation | 2024 |
| 9 | Defending Against Indirect Prompt Injection in Multi-Agent Systems | Chen et al. | 2024 |
| 10 | InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents | Zhan et al. | 2024 |
| 11 | TensorTrust: Interpretable Prompt Injection Attacks | Toyer et al. | 2024 |
| 12 | Prompt Guard: Safe Prompting for LLMs | Meta AI | 2024 |
| 13 | Constitutional AI: Harmlessness from AI Feedback | Anthropic | 2022 |
| 14 | AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses for LLM Agents | Debenedetti et al. | 2024 |
| 15 | Spotlighting: Defending Against Prompt Injection via Input Delimiting | Hines et al., Microsoft | 2024 |
| 16 | StruQ: Defending Against Prompt Injection with Structured Queries | Chen et al. | 2024 |
| 17 | Signed-Prompt: A New Approach to Prevent Prompt Injection Attacks | Wu et al. | 2024 |
| 18 | Baseline Defenses for Adversarial Attacks Against Aligned Language Models | Jain et al. | 2023 |
| 19 | Purple Llama CyberSecEval: A Secure Coding Benchmark for LLMs | Bhatt et al., Meta | 2024 |
| 20 | EU AI Act: Regulation 2024/1689 on Artificial Intelligence | European Parliament | 2024 |

## Contributing

### Adding Detection Rules

1. Add patterns to `scripts/seed-patterns.ts` following the existing format
2. Each pattern requires: `id`, `regex` or `embedding`, `killChainPhase`, `severity`, `description`
3. Run `npm run db:seed` to load
4. Run `npm run self-test` to verify no regressions

### Reporting False Positives

Open an issue with:
- The input that triggered the false positive (redact sensitive content)
- The `scannerId` and `killChainPhase` from the result
- Your ShieldX version and configuration

### Adding Pattern Categories

1. Create a new JSON file under the attack corpus directory
2. Follow the schema: `{ patterns: [{ input, expectedPhase, expectedSeverity }] }`
3. Run the benchmark suite: `npm run benchmark`

### Development

```bash
git clone https://gitea.context-x.org/rene/shieldx.git
cd shieldx
npm install
npm run build
npm test
npm run test:coverage  # Target: 80%+
```

## License

Apache License 2.0 -- see [LICENSE](LICENSE) for details.

Copyright 2026 Context X. Open source under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0).
