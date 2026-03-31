# ShieldX Architecture

## Overview

ShieldX is a 10-layer defense pipeline orchestrated by a single `ShieldX` class. Each layer is independently toggleable, runs in isolation, and never blocks the pipeline if it fails. The orchestrator uses `Promise.allSettled` for parallel execution and graceful degradation.

## 10-Layer Pipeline

### L0: Preprocessing

**Modules:** `UnicodeNormalizer`, `TokenizerNormalizer`, `CompressedPayloadDetector`

The preprocessing layer normalizes input before any detection runs. This is the only sequential layer -- all downstream scanners operate on the normalized output.

- **Unicode Normalization**: NFKC normalization, invisible character removal, homoglyph detection, Bidi override stripping. Catches attacks that use visually identical characters to bypass pattern matching.
- **Tokenizer Normalization**: Normalizes tokenizer-specific artifacts (zero-width joiners, soft hyphens, token-boundary exploits). Prevents attacks that exploit differences between how humans read text and how tokenizers split it.
- **Compressed Payload Detection**: Detects and decodes Base64, gzip, hex-encoded, and other compressed payloads embedded in input. Decoded content is appended to the normalized input so downstream scanners can analyze it.

**Performance:** <0.5ms combined. Always enabled (zero cost, high impact).

### L1: Rule Engine

**Module:** `RuleEngine`

Pattern-matching engine with 500+ built-in regex rules organized by kill chain phase. Rules are loaded from a seeded pattern store and can be extended at runtime through the learning engine.

- Category-based rule organization (injection markers, role overrides, data exfiltration patterns)
- Per-rule kill chain phase and severity mapping
- Hot-reloadable: new rules from the learning engine take effect without restart

**Performance:** <2ms for 500+ patterns.

### L2: Sentinel Classifier

**Module:** `SentinelClassifier` (opt-in)

Machine learning binary classifier trained to distinguish benign prompts from injection attempts. Operates on token-level features extracted from the normalized input.

- Requires model download (not included in default install)
- Outputs confidence score mapped to threat level via configurable thresholds
- Runs in parallel with L1

**Performance:** <10ms.

### L3: Embedding Scanners

**Modules:** `EmbeddingStore`, `EmbeddingScanner`, `EmbeddingAnomalyDetector`

Semantic similarity analysis using vector embeddings. Compares input against a database of known attack embeddings stored in PostgreSQL with pgvector.

- **Similarity Scanner**: Cosine similarity against known attack vectors. Catches paraphrased variants of known attacks that bypass regex patterns.
- **Anomaly Detector**: Statistical outlier detection on embedding space. Identifies inputs that are structurally unusual compared to the conversation baseline.

**Performance:** <200ms (requires Ollama for embedding generation).

### L4: Entropy Analysis

**Module:** `EntropyScanner`

Information-theoretic analysis of input text. Measures Shannon entropy, character distribution, and n-gram statistics.

- High entropy can indicate encoded payloads, obfuscated injection, or adversarial token sequences
- Low entropy in unexpected contexts can indicate template-based attacks
- Adaptive thresholds based on conversation baseline

**Performance:** <1ms.

### L5: Attention Pattern Analysis

**Module:** `AttentionScanner` (opt-in)

Analyzes attention weight distribution from Ollama models to detect inputs that cause abnormal attention patterns.

- Detects attention hijacking (injection that captures disproportionate model attention)
- Identifies attention-blind spots (content designed to avoid model attention)
- Requires Ollama with attention output support

**Performance:** <200ms. Runs in parallel with L3 and L4.

### L6: Behavioral Monitoring

**Modules:** `ConversationTracker`, `IntentMonitor`, `ContextIntegrity`, `SessionProfiler`, `MemoryIntegrityGuard`, `AnomalyDetector`, `ContextDriftDetector`, `TrustTagger`

Multi-turn conversation analysis that detects attacks spanning multiple messages.

- **Conversation Tracker**: Maintains conversation state, detects turn-over-turn pattern shifts, identifies multi-step attack sequences.
- **Intent Monitor**: Tracks declared vs. actual intent. Flags when the behavioral pattern diverges from the stated task description.
- **Context Integrity**: Verifies that the context window has not been poisoned by injected content. Measures context poison score.
- **Session Profiler**: Builds a behavioral baseline per session and flags anomalous deviations.
- **Memory Integrity Guard**: Detects unauthorized modifications to conversation memory or cached instructions.
- **Trust Tagger**: Assigns trust scores per data source using Bayesian updating.

**Performance:** <5ms combined.

### L7: MCP Guard

**Modules:** `MCPInspector`, `ToolCallInterceptor`, `PrivilegeChecker`, `ToolChainGuard`, `ToolPoisonDetector`, `ResourceGovernor`, `DecisionGraphAnalyzer`, `ManifestVerifier`, `OllamaGuard`

Purpose-built protection for Model Context Protocol tool calls.

- **Privilege Checker**: Enforces least-privilege per session. Only tools in the allowed set can execute.
- **Tool Chain Guard**: Records tool call sequences and detects suspicious patterns (e.g., read credentials then send HTTP request).
- **Tool Poison Detector**: Analyzes tool definitions and results for embedded injection attempts.
- **Resource Governor**: Enforces token and API call budgets per session.
- **Decision Graph Analyzer**: Builds and analyzes the agent decision tree for manipulation patterns.
- **Manifest Verifier**: Cryptographic verification of MCP server manifests.

**Performance:** <3ms (without Ollama-dependent features).

### L8: Sanitization

**Modules:** `InputSanitizer`, `OutputSanitizer`, `CredentialRedactor`, `DelimiterHardener`, `SpotlightingEncoder`, `StructuredQueryEncoder`, `SignedPromptVerifier`, `PolymorphicAssembler`

Input and output sanitization to strip injections while preserving legitimate content.

- **Input Sanitizer**: Removes identified injection markers, delimiter manipulation, and role override attempts.
- **Output Sanitizer**: Strips system prompt leakage, script injection, and tool-call injection from LLM responses.
- **Credential Redactor**: Detects and masks API keys, tokens, passwords, and PII in output.
- **Delimiter Hardener**: Strengthens prompt delimiters to resist delimiter confusion attacks.
- **Spotlighting Encoder**: Implements the Microsoft Spotlighting technique -- marks data boundaries to help the LLM distinguish instructions from data.
- **Structured Query Encoder**: Encodes user input into structured query format to prevent injection.
- **Signed Prompt Verifier**: Verifies cryptographic signatures on system prompts.

**Performance:** <1ms.

### L9: Output Validation

**Modules:** `OutputValidator`, `CanaryManager`, `LeakageDetector`, `RAGShield`, `RoleIntegrityChecker`, `ScopeValidator`, `IntentGuardValidator`

Post-generation validation of LLM output before it reaches the user.

- **Canary Manager**: Injects unique canary tokens into system prompts. If they appear in output, system prompt extraction is confirmed.
- **Leakage Detector**: Scans output for system prompt fragments, internal tool descriptions, and sensitive configuration.
- **RAG Shield**: Validates RAG-retrieved documents for injection, scores document integrity, tracks provenance.
- **Role Integrity Checker**: Verifies the LLM has not adopted an unauthorized role.
- **Scope Validator**: Ensures the response stays within the declared scope of the task.

**Performance:** <2ms.

## Data Flow Diagram

```
User Input
    |
    v
[L0: Preprocess] -----> normalized input
    |
    |  +------------------+------------------+
    |  |                  |                  |
    v  v                  v                  v
  [L1: Rules]      [L2: Sentinel]     (parallel)
    |                     |
    +----------+----------+
               |
    +----------+----------+----------+
    |          |          |          |
    v          v          v          v
 [L3: Embed] [L4: Entropy] [L5: Attn] [Canary/YARA/Indirect]
    |          |          |          |
    +----------+----------+----------+
               |
               v
         [L6: Behavioral]
               |
               v
         [L7: MCP Guard] (if tool call context)
               |
               v
         [Aggregator] -- collects all ScanResult[]
               |
         +-----+-----+
         |           |
         v           v
  [Kill Chain    [Healing
   Mapper]       Orchestrator]
         |           |
         +-----+-----+
               |
               v
         [L8: Sanitize] (if action == 'sanitize')
               |
               v
         [L9: Validate] (for output scans)
               |
               v
        ShieldXResult
               |
               v
        [Evolution Engine] (async, background)
               |
         +-----+-----+-----+-----+
         |     |     |     |     |
         v     v     v     v     v
       [GAN] [Drift] [Active] [Fed] [Attack
       Red    Detect  Learn   Sync   Graph]
       Team
```

## Module Dependency Graph

```
@shieldx/core
  |
  +-- core/
  |     +-- ShieldX.ts         (orchestrator -- imports all layers)
  |     +-- config.ts          (default config, merge utility)
  |     +-- logger.ts          (Pino structured logging)
  |
  +-- types/
  |     +-- detection.ts       (ScanResult, ShieldXResult, ShieldXConfig, etc.)
  |     +-- healing.ts         (HealingStrategy, HealingResponse)
  |     +-- learning.ts        (PatternRecord, LearningStats, DriftReport)
  |     +-- behavioral.ts      (ConversationState, IntentVector, SessionProfile)
  |     +-- killchain.ts       (KillChainPhaseDetail, KillChainClassification)
  |     +-- compliance.ts      (ATLASMapping, OWASPMapping, EUAIActReport)
  |     +-- trust.ts           (TrustTagType, DataOrigin, TrustPolicy)
  |
  +-- preprocessing/           (L0 -- no external deps)
  |     +-- UnicodeNormalizer.ts
  |     +-- TokenizerNormalizer.ts
  |     +-- CompressedPayloadDetector.ts
  |
  +-- detection/               (L1-L2 -- depends on types/)
  |     +-- RuleEngine.ts
  |
  +-- behavioral/              (L6 -- depends on types/)
  |     +-- ConversationTracker.ts
  |     +-- IntentMonitor.ts
  |     +-- ContextIntegrity.ts
  |     +-- SessionProfiler.ts
  |     +-- MemoryIntegrityGuard.ts
  |     +-- AnomalyDetector.ts
  |     +-- ContextDriftDetector.ts
  |     +-- TrustTagger.ts
  |     +-- ToolCallValidator.ts
  |     +-- KillChainMapper.ts
  |
  +-- mcp-guard/               (L7 -- depends on types/)
  |     +-- MCPInspector.ts
  |     +-- ToolCallInterceptor.ts
  |     +-- PrivilegeChecker.ts
  |     +-- ToolChainGuard.ts
  |     +-- ToolPoisonDetector.ts
  |     +-- ResourceGovernor.ts
  |     +-- DecisionGraphAnalyzer.ts
  |     +-- ManifestVerifier.ts
  |     +-- OllamaGuard.ts
  |
  +-- sanitization/            (L8 -- depends on types/)
  |     +-- InputSanitizer.ts
  |     +-- OutputSanitizer.ts
  |     +-- CredentialRedactor.ts
  |     +-- DelimiterHardener.ts
  |     +-- SpotlightingEncoder.ts
  |     +-- StructuredQueryEncoder.ts
  |     +-- SignedPromptVerifier.ts
  |     +-- PolymorphicAssembler.ts
  |
  +-- validation/              (L9 -- depends on types/)
  |     +-- OutputValidator.ts
  |     +-- CanaryManager.ts
  |     +-- LeakageDetector.ts
  |     +-- RAGShield.ts
  |     +-- RoleIntegrityChecker.ts
  |     +-- ScopeValidator.ts
  |     +-- IntentGuardValidator.ts
  |
  +-- healing/                 (depends on types/, behavioral/)
  |     +-- HealingOrchestrator.ts
  |     +-- FallbackResponder.ts
  |     +-- IncidentReporter.ts
  |     +-- PromptReconstructor.ts
  |     +-- SessionManager.ts
  |
  +-- learning/                (depends on types/, pg, pgvector)
  |     +-- PatternStore.ts
  |     +-- PatternEvolver.ts
  |     +-- EmbeddingStore.ts
  |     +-- RedTeamEngine.ts
  |     +-- DriftDetector.ts
  |     +-- ActiveLearner.ts
  |     +-- FeedbackProcessor.ts
  |     +-- FederatedSync.ts
  |     +-- AttackGraph.ts
  |     +-- ConversationLearner.ts
  |     +-- ThresholdAdaptor.ts
  |
  +-- compliance/              (depends on types/)
  |     +-- ATLASMapper.ts
  |     +-- OWASPMapper.ts
  |     +-- EUAIActReporter.ts
  |     +-- ReportGenerator.ts
  |
  +-- supply-chain/            (depends on types/)
  |     +-- SupplyChainVerifier.ts
  |     +-- ModelProvenanceChecker.ts
  |
  +-- integrations/            (depends on core/)
        +-- nextjs/
        +-- ollama/
        +-- anthropic/
```

## External Dependencies

| Dependency | Purpose | Required |
|------------|---------|----------|
| `pg` | PostgreSQL client for pattern/embedding storage | Only if `storageBackend: 'postgresql'` |
| `pgvector` | Vector similarity operations in PostgreSQL | Only if embedding scanner enabled with postgresql |
| `zod` | Runtime schema validation for configuration and input | Yes |
| `pino` | Structured JSON logging | Yes |

## Performance Characteristics

### Parallel Execution

Layers that have no data dependency on each other run in parallel:
- L1 and L2 run in parallel
- L3, L4, L5, Canary, YARA, and Indirect scanners all run in parallel
- Within L6, conversation tracking, intent monitoring, and context integrity run in parallel

### Graceful Degradation

Every scanner invocation is wrapped in `safeRunScanner()`:
- Catches all exceptions
- Logs the failure with scanner ID and error message
- Returns empty results (the scanner is skipped, not the pipeline)

`Promise.allSettled` ensures a slow or failing scanner never blocks others. A scanner that times out after its expected latency window simply contributes no results to the aggregation.

### Zero-Cost Defaults

The default configuration enables only layers that have no external dependencies:
- L0 (preprocessing): pure computation, <0.5ms
- L1 (rule engine): pure computation, <2ms
- L6 (behavioral): in-memory state, <5ms
- L7 (MCP guard): in-memory checks, <3ms
- L8 (sanitization): pure computation, <1ms

Ollama-dependent layers (L3 embedding, L5 attention) and model-dependent layers (L2 sentinel) are opt-in.

### Memory Footprint

- Default configuration (memory backend): ~5MB base + ~1KB per active session
- With PostgreSQL backend: ~2MB base (connection pool) + patterns stored externally
- Rule engine: ~500KB for 500+ compiled regex patterns
- Embedding cache: configurable, default 10,000 vectors in memory

## Build Output

ShieldX builds to three formats via tsup:
- **CJS**: `dist/index.js` (CommonJS for Node.js require())
- **ESM**: `dist/index.mjs` (ES modules for import)
- **DTS**: `dist/index.d.ts` (TypeScript declarations)

Integration subpaths are available at:
- `@shieldx/core/nextjs`
- `@shieldx/core/ollama`
- `@shieldx/core/anthropic`
