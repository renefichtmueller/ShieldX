# Configuration Reference

## Overview

ShieldX configuration is provided as a partial object to the `ShieldX` constructor. All fields are optional -- defaults are applied via `mergeConfig()`. Configuration is immutable after construction.

```typescript
import { ShieldX } from '@shieldx/core'

const shield = new ShieldX({
  // Only specify fields you want to override
  scanners: { sentinel: true },
  learning: { storageBackend: 'postgresql', connectionString: process.env.DATABASE_URL },
})
```

The full config type is `ShieldXConfig` defined in `src/types/detection.ts`.

---

## thresholds

Confidence score boundaries that map scanner output to threat severity levels.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `thresholds.low` | `number` | `0.3` | Minimum confidence score for `low` severity. Scores below this are classified as `none`. |
| `thresholds.medium` | `number` | `0.5` | Minimum confidence score for `medium` severity. |
| `thresholds.high` | `number` | `0.7` | Minimum confidence score for `high` severity. |
| `thresholds.critical` | `number` | `0.9` | Minimum confidence score for `critical` severity. Only the highest-confidence detections reach this level. |

**Notes:**
- Thresholds must be strictly ascending: `low < medium < high < critical`
- The `ThresholdAdaptor` in the learning engine may recommend adjustments based on observed false positive/negative rates
- Lower thresholds catch more attacks but increase false positives
- Higher thresholds reduce false positives but may miss subtle attacks

---

## scanners

Toggle individual scanner modules. Each scanner can be independently enabled or disabled.

| Option | Type | Default | Requires | Description |
|--------|------|---------|----------|-------------|
| `scanners.rules` | `boolean` | `true` | Nothing | L1 rule engine. 500+ regex patterns. Always recommended. |
| `scanners.sentinel` | `boolean` | `false` | Model download | L2 ML binary classifier. Requires downloading the Sentinel model. |
| `scanners.constitutional` | `boolean` | `false` | Model download | Constitutional AI classifier. Evaluates input against constitutional principles. |
| `scanners.embedding` | `boolean` | `true` | Ollama | L3 embedding similarity scanner. Compares input against known attack embeddings. |
| `scanners.embeddingAnomaly` | `boolean` | `true` | Ollama | L3 embedding anomaly detector. Statistical outlier detection in embedding space. |
| `scanners.entropy` | `boolean` | `true` | Nothing | L4 entropy analysis. Detects encoded/obfuscated payloads via information theory. |
| `scanners.yara` | `boolean` | `false` | YARA binary | YARA rule matching. Requires the `yara` binary installed on the system. |
| `scanners.attention` | `boolean` | `false` | Ollama (attention output) | L5 attention pattern analysis. Requires Ollama configured to return attention weights. |
| `scanners.canary` | `boolean` | `true` | Nothing | Canary token injection and detection. Injects tokens in system prompts to detect extraction. |
| `scanners.indirect` | `boolean` | `true` | Nothing | Indirect injection detection. Scans content from external sources (tool results, documents). |
| `scanners.selfConsciousness` | `boolean` | `false` | LLM API call | LLM self-check. Asks a second LLM whether the input is an injection. Expensive per-call. |
| `scanners.crossModel` | `boolean` | `false` | Multiple LLM endpoints | Cross-model verification. Compares responses from multiple models for consistency. |
| `scanners.behavioral` | `boolean` | `true` | Nothing | Enables the L6 behavioral monitoring suite. Individual behavioral features are controlled under the `behavioral` section. |
| `scanners.unicode` | `boolean` | `true` | Nothing | L0 Unicode normalization scanner. Zero cost, always recommended. |
| `scanners.tokenizer` | `boolean` | `true` | Nothing | L0 tokenizer normalization scanner. Zero cost. |
| `scanners.compressedPayload` | `boolean` | `true` | Nothing | L0 compressed payload detection. Detects Base64, gzip, hex payloads. |

**Minimal configuration** (zero external dependencies):

```typescript
const shield = new ShieldX({
  scanners: {
    rules: true,
    sentinel: false,
    constitutional: false,
    embedding: false,
    embeddingAnomaly: false,
    entropy: true,
    yara: false,
    attention: false,
    canary: true,
    indirect: true,
    selfConsciousness: false,
    crossModel: false,
    behavioral: true,
    unicode: true,
    tokenizer: true,
    compressedPayload: true,
  },
})
```

---

## healing

Controls the self-healing engine that determines what action to take when a threat is detected.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `healing.enabled` | `boolean` | `true` | Master toggle for the healing engine. When disabled, detected threats are logged but no action is taken. |
| `healing.autoSanitize` | `boolean` | `true` | When the healing action is `sanitize`, automatically produce a sanitized version of the input. |
| `healing.sessionReset` | `boolean` | `true` | Allow the healing engine to reset sessions to clean checkpoints when persistence attacks are detected. |
| `healing.phaseStrategies` | `Record<KillChainPhase, HealingAction>` | See below | Maps each kill chain phase to a healing action. |

### Phase Strategies

| Kill Chain Phase | Default Action | Available Actions |
|------------------|----------------|-------------------|
| `initial_access` | `sanitize` | `allow`, `sanitize`, `warn`, `block`, `reset`, `incident` |
| `privilege_escalation` | `block` | `allow`, `sanitize`, `warn`, `block`, `reset`, `incident` |
| `reconnaissance` | `block` | `allow`, `sanitize`, `warn`, `block`, `reset`, `incident` |
| `persistence` | `reset` | `allow`, `sanitize`, `warn`, `block`, `reset`, `incident` |
| `command_and_control` | `incident` | `allow`, `sanitize`, `warn`, `block`, `reset`, `incident` |
| `lateral_movement` | `incident` | `allow`, `sanitize`, `warn`, `block`, `reset`, `incident` |
| `actions_on_objective` | `incident` | `allow`, `sanitize`, `warn`, `block`, `reset`, `incident` |

### Healing Actions Explained

| Action | Behavior |
|--------|----------|
| `allow` | Input passes through. No intervention. |
| `sanitize` | Injection markers stripped. Clean input returned as `sanitizedInput`. |
| `warn` | Input passes but incident is logged with context. |
| `block` | Input rejected. No sanitized version produced. |
| `reset` | Session restored to last clean checkpoint. Poisoned context purged. |
| `incident` | Full incident report generated. Session quarantined. Compliance mappings produced. |

---

## learning

Controls the self-learning and pattern evolution engine.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `learning.enabled` | `boolean` | `true` | Master toggle for the learning engine. When disabled, no pattern evolution occurs. |
| `learning.storageBackend` | `'postgresql' \| 'sqlite' \| 'memory'` | `'memory'` | Where patterns and embeddings are stored. `memory` is suitable for development and single-process deployments. `postgresql` is recommended for production (supports pgvector). |
| `learning.connectionString` | `string?` | `undefined` | Database connection URL. Required when `storageBackend` is `postgresql` or `sqlite`. Format: `postgresql://user:pass@host:5432/dbname` |
| `learning.feedbackLoop` | `boolean` | `true` | Process user feedback submitted via `submitFeedback()`. Feedback refines classifier weights and pattern confidence. |
| `learning.communitySync` | `boolean` | `false` | Sync anonymized pattern hashes with the community endpoint. Disabled by default. See [self-evolution.md](./self-evolution.md) for privacy details. |
| `learning.communitySyncUrl` | `string?` | `undefined` | URL of the community sync endpoint. Required when `communitySync` is `true`. |
| `learning.driftDetection` | `boolean` | `true` | Monitor for concept drift in attack patterns. Triggers alerts and accelerated red team cycles when drift is detected. |
| `learning.activelearning` | `boolean` | `true` | Identify uncertain samples at the classifier decision boundary for human review. |
| `learning.attackGraph` | `boolean` | `true` | Build a directed graph of attack pattern relationships. Enables predictive detection and campaign identification. |

---

## behavioral

Controls the L6 behavioral monitoring suite.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `behavioral.enabled` | `boolean` | `true` | Master toggle for all behavioral monitoring. |
| `behavioral.baselineWindow` | `number` | `10` | Number of messages used to establish the session behavioral baseline. Messages within this window are used to compute "normal" behavior statistics. |
| `behavioral.driftThreshold` | `number` | `0.4` | Threshold for behavioral drift alerts. Value between 0 and 1. Lower values are more sensitive. |
| `behavioral.intentTracking` | `boolean` | `true` | Track intent shifts across conversation turns. Detects when behavior diverges from the stated task. |
| `behavioral.conversationTracking` | `boolean` | `true` | Track conversation patterns. Detects multi-turn attack sequences. |
| `behavioral.contextIntegrity` | `boolean` | `true` | Verify context window integrity. Detects context poisoning. |
| `behavioral.memoryIntegrity` | `boolean` | `true` | Guard against unauthorized modifications to conversation memory. |
| `behavioral.bayesianTrustScoring` | `boolean` | `true` | Assign and update trust scores per data source using Bayesian inference. |

---

## mcpGuard

Controls the L7 MCP (Model Context Protocol) tool-call protection.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `mcpGuard.enabled` | `boolean` | `true` | Master toggle for MCP protection. |
| `mcpGuard.ollamaEndpoint` | `string?` | `'http://localhost:11434'` | Ollama API endpoint for tool analysis and decision graph features. |
| `mcpGuard.validateToolCalls` | `boolean` | `true` | Validate all tool invocations through the `validateToolCall()` method. |
| `mcpGuard.privilegeCheck` | `boolean` | `true` | Enforce least-privilege: only tools in the session's `allowedTools` set can execute. |
| `mcpGuard.toolChainGuard` | `boolean` | `true` | Record tool call sequences and detect suspicious patterns (e.g., credential read followed by HTTP send). |
| `mcpGuard.resourceGovernor` | `boolean` | `true` | Enforce token and API call budgets per session. |
| `mcpGuard.decisionGraph` | `boolean` | `false` | Build and analyze agent decision trees for manipulation patterns. Requires Ollama. |
| `mcpGuard.manifestVerification` | `boolean` | `false` | Verify MCP server manifests using cryptographic signatures. Requires RSA key configuration. |

---

## ppa

Prompt/Response Address Space Randomization. Randomizes prompt structure to make targeted injection harder.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ppa.enabled` | `boolean` | `true` | Enable prompt randomization. |
| `ppa.randomizationLevel` | `'low' \| 'medium' \| 'high'` | `'medium'` | Degree of structural randomization applied. `low`: minimal delimiter variation. `medium`: delimiter + ordering variation. `high`: full structural randomization including decoy sections. |

---

## canary

Canary token system for detecting system prompt extraction.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `canary.enabled` | `boolean` | `true` | Enable canary token injection and detection. |
| `canary.tokenCount` | `number` | `3` | Number of unique canary tokens injected per system prompt. Higher count increases detection confidence but uses more prompt tokens. |
| `canary.rotationInterval` | `number` | `3600` | Token rotation interval in seconds. Tokens are replaced at this interval to limit replay-based evasion. |

---

## ragShield

Protection for RAG (Retrieval-Augmented Generation) pipelines.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ragShield.enabled` | `boolean` | `true` | Enable RAG protection. |
| `ragShield.documentIntegrityScoring` | `boolean` | `true` | Score retrieved documents for injection risk before they enter the LLM context. |
| `ragShield.embeddingAnomalyDetection` | `boolean` | `true` | Detect anomalous embeddings in the vector store that may indicate poisoning. |
| `ragShield.provenanceTracking` | `boolean` | `true` | Track document provenance (source, ingestion time, modification history). |

---

## compliance

Compliance reporting and framework mapping.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `compliance.mitreAtlas` | `boolean` | `true` | Map incidents to MITRE ATLAS techniques and tactics. |
| `compliance.owaspLlm` | `boolean` | `true` | Map incidents to OWASP LLM Top 10 2025 risk categories. |
| `compliance.euAiAct` | `boolean` | `false` | Generate EU AI Act compliance reports (Articles 9, 12, 14, 15). Opt-in because it requires additional data collection and audit trail storage. |

---

## logging

Structured logging configuration using Pino.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `logging.level` | `'silent' \| 'error' \| 'warn' \| 'info' \| 'debug'` | `'info'` | Log verbosity level. `debug` includes per-scanner latency and intermediate results. |
| `logging.structured` | `boolean` | `true` | Output logs as JSON (Pino default). Set to `false` for human-readable output in development. |
| `logging.incidentLog` | `boolean` | `true` | Maintain a dedicated incident log separate from general application logs. |

---

## Environment Variables

ShieldX reads the following environment variables as fallbacks:

| Variable | Maps To | Description |
|----------|---------|-------------|
| `SHIELDX_DB_URL` | `learning.connectionString` | Database connection URL |
| `SHIELDX_OLLAMA_URL` | `mcpGuard.ollamaEndpoint` | Ollama API endpoint |
| `SHIELDX_LOG_LEVEL` | `logging.level` | Log level override |
| `SHIELDX_COMMUNITY_SYNC_URL` | `learning.communitySyncUrl` | Community sync endpoint |

Environment variables are only used when the corresponding config field is not explicitly set.

---

## Example Configurations

### Development (Zero Dependencies)

```typescript
const shield = new ShieldX({
  scanners: { embedding: false, attention: false, sentinel: false },
  learning: { storageBackend: 'memory' },
  logging: { level: 'debug', structured: false },
})
```

### Production (Full Pipeline)

```typescript
const shield = new ShieldX({
  scanners: { sentinel: true, embedding: true, attention: true },
  learning: {
    storageBackend: 'postgresql',
    connectionString: process.env.SHIELDX_DB_URL,
    communitySync: true,
    communitySyncUrl: 'https://sync.shieldx.dev/v1/patterns',
  },
  compliance: { euAiAct: true },
  logging: { level: 'info' },
})
```

### High Security (Maximum Protection)

```typescript
const shield = new ShieldX({
  thresholds: { low: 0.2, medium: 0.4, high: 0.6, critical: 0.8 },
  scanners: {
    sentinel: true,
    constitutional: true,
    embedding: true,
    attention: true,
    yara: true,
    selfConsciousness: true,
  },
  healing: {
    phaseStrategies: {
      initial_access: 'block',       // Block even initial attempts
      privilege_escalation: 'incident',
      reconnaissance: 'incident',
      persistence: 'incident',
      command_and_control: 'incident',
      lateral_movement: 'incident',
      actions_on_objective: 'incident',
    },
  },
  ppa: { randomizationLevel: 'high' },
  canary: { tokenCount: 5, rotationInterval: 600 },
  compliance: { euAiAct: true },
})
```

### Minimal Latency (Speed-Optimized)

```typescript
const shield = new ShieldX({
  scanners: {
    rules: true,
    sentinel: false,
    embedding: false,
    embeddingAnomaly: false,
    attention: false,
    yara: false,
    selfConsciousness: false,
    crossModel: false,
  },
  behavioral: { enabled: false },
  mcpGuard: { enabled: false },
  learning: { enabled: false },
})
// Expected latency: <5ms
```
