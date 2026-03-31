# Self-Evolution Engine

## Overview

ShieldX models its self-learning system on biological immune systems. The defense evolves continuously without manual rule updates. Five mechanisms work together: innate immunity (static rules), adaptive immunity (ML classifiers), immune memory (vector database), antibody generation (GAN red team), and herd immunity (federated sync).

All evolution happens locally by default. No data leaves your infrastructure unless you explicitly enable community sync.

## Architecture

```
                    New Scan Results
                          |
            +-------------+-------------+
            |             |             |
            v             v             v
     [Feedback       [Drift         [Attack
      Processor]      Detector]      Graph]
            |             |             |
            v             v             v
     [Active         [Threshold     [Pattern
      Learner]        Adaptor]       Evolver]
            |             |             |
            +------+------+------+-----+
                   |             |
                   v             v
            [Pattern Store]  [Embedding Store]
                   |             |
                   +------+------+
                          |
                   +------+------+
                   |             |
                   v             v
            [Red Team       [Federated
             Engine]         Sync]
```

## 1. Innate Immunity (Static Rules)

### Concept

Like the body's innate immune system (skin, mucous membranes, white blood cells), innate immunity provides immediate, non-specific defense against known threats. These rules are present from installation and never change at runtime.

### Implementation

The `RuleEngine` loads 500+ regex patterns from the seed database. These patterns are organized by:

- **Kill chain phase**: each pattern maps to a specific phase
- **Severity**: default threat level for the pattern
- **Category**: injection type (role override, delimiter manipulation, encoding trick, etc.)

Patterns are compiled once at initialization and evaluated sequentially with short-circuit on first critical match.

### Characteristics

| Property | Value |
|----------|-------|
| Latency | <2ms for 500+ patterns |
| False positive rate | Low (patterns are precise, not probabilistic) |
| Evasion resistance | Low (attackers can rephrase to avoid regex) |
| Update mechanism | Seed script (`npm run db:seed`) |

### Strengths and Limitations

Strengths:
- Zero latency overhead
- Deterministic, auditable, explainable
- No external dependencies
- Catches the majority of unsophisticated attacks

Limitations:
- Cannot detect novel or paraphrased attacks
- Regex patterns are brittle against encoding tricks (handled by L0 preprocessing)
- Cannot capture semantic meaning

---

## 2. Adaptive Immunity (ML Classifiers)

### Concept

Like T-cells and B-cells that learn to recognize specific pathogens, adaptive immunity develops targeted defenses against attacks that bypass static rules. These classifiers improve over time through exposure to new attack patterns and feedback.

### Implementation

**Sentinel Classifier** (L2): Binary classifier trained on labeled examples of benign and malicious prompts. Outputs a confidence score that maps to threat levels via configurable thresholds.

**Active Learner** (`src/learning/ActiveLearner.ts`): Identifies samples near the classifier's decision boundary -- inputs where the model is most uncertain. These samples are the most valuable for improving the classifier and are prioritized for human review.

**Feedback Processor** (`src/learning/FeedbackProcessor.ts`): Processes `submitFeedback()` calls to refine classifier weights. True positives reinforce existing patterns. False positives adjust the decision boundary to avoid future misclassification.

**Threshold Adaptor** (`src/learning/ThresholdAdaptor.ts`): Dynamically adjusts confidence thresholds based on observed false positive and false negative rates. If the false positive rate exceeds a configurable target, thresholds are raised. If the false negative rate increases (detected through red team testing), thresholds are lowered.

### Learning Loop

```
User Input -> Scan Pipeline -> ShieldXResult
                                    |
                              User Feedback
                              (true/false positive)
                                    |
                            Feedback Processor
                                    |
                    +---------------+---------------+
                    |               |               |
              Pattern Store   Classifier Weights  Thresholds
              (new/refined    (retrained on       (adjusted by
               patterns)       feedback)           ThresholdAdaptor)
```

### Characteristics

| Property | Value |
|----------|-------|
| Latency | <10ms per classification |
| False positive rate | Adaptive (adjusts via feedback) |
| Evasion resistance | Medium (learns from confirmed attacks) |
| Update mechanism | Continuous via feedback loop |

---

## 3. Immune Memory (Vector Database)

### Concept

Like immunological memory that enables faster response to previously encountered pathogens, the embedding store provides long-term memory of every attack pattern ShieldX has seen. New inputs are compared against this memory for semantic similarity, catching paraphrased variants.

### Implementation

**Embedding Store** (`src/learning/EmbeddingStore.ts`): Stores attack pattern embeddings in PostgreSQL with pgvector. Each embedding is associated with its kill chain phase, severity, scanner origin, and confirmation status.

**Semantic Similarity**: New inputs are embedded (via Ollama) and compared against stored attack vectors using cosine similarity. A match above the configured threshold triggers detection even if no regex pattern or classifier fires.

**Conversation Learner** (`src/learning/ConversationLearner.ts`): Learns from conversation-level attack patterns -- multi-turn sequences that individually appear benign but collectively form an attack. Stores conversation fingerprints, not individual messages.

### Storage Schema

```
Pattern Record:
  id: string
  embedding: float[] (pgvector)
  killChainPhase: KillChainPhase
  severity: ThreatLevel
  source: 'builtin' | 'learned' | 'community' | 'red_team'
  confirmedBy: 'human' | 'classifier' | 'red_team' | null
  createdAt: timestamp
  lastMatchedAt: timestamp
  matchCount: number
  falsePositiveCount: number
```

### Characteristics

| Property | Value |
|----------|-------|
| Latency | <200ms (embedding generation + similarity search) |
| False positive rate | Medium (semantic similarity can match unrelated content) |
| Evasion resistance | High (semantic meaning is preserved across paraphrasing) |
| Update mechanism | Continuous -- new confirmed patterns added automatically |

---

## 4. Antibody Generation (GAN Red Team)

### Concept

Like the immune system generating antibodies to neutralize specific pathogens, the red team engine proactively generates new attack variants to test the defense pipeline before real attackers discover those variants.

### Implementation

**Red Team Engine** (`src/learning/RedTeamEngine.ts`): Takes known attack patterns and generates variants using adversarial mutation strategies:

| Mutation Strategy | Description |
|-------------------|-------------|
| Synonym replacement | Replaces key terms with synonyms that preserve attack intent |
| Encoding shift | Re-encodes payloads using different encoding schemes |
| Structural rearrangement | Changes the order of injection components |
| Delimiter mutation | Uses different delimiter styles |
| Language mixing | Introduces multilingual elements |
| Token splitting | Splits critical words across token boundaries |
| Homoglyph substitution | Replaces characters with visually similar Unicode variants |
| Case manipulation | Changes capitalization patterns |

**Pattern Evolver** (`src/learning/PatternEvolver.ts`): Orchestrates the red team process:

1. Select a set of known attack patterns from the pattern store
2. Generate N variants per pattern using mutation strategies
3. Run each variant through the full ShieldX pipeline
4. Variants that bypass detection are flagged as "gap patterns"
5. Gap patterns are added to the pattern store with source `'red_team'`
6. The rule engine and classifiers are updated to detect the new patterns

### Red Team Cycle

```
Known Patterns --> [Mutation Engine] --> Variant Attacks
                                              |
                                     [ShieldX Pipeline]
                                              |
                                  +--------+--------+
                                  |                 |
                              Detected          Bypassed
                              (good)            (gap found!)
                                                    |
                                            [Pattern Store]
                                            [Classifier Update]
                                            [Embedding Store]
```

### Self-Test

The `npm run self-test` command executes a full red team cycle against the current pipeline and reports:

- Total variants generated
- Attack success rate (ASR) -- percentage that bypassed detection
- New gap patterns discovered
- Pipeline coverage improvement after adding gap patterns

### Characteristics

| Property | Value |
|----------|-------|
| Execution frequency | Configurable (default: weekly batch, or on-demand) |
| Variants per pattern | Configurable (default: 50) |
| Gap discovery rate | Varies (typically 5-15% of variants bypass detection) |
| Update mechanism | Automatic -- gap patterns added to stores immediately |

---

## 5. Herd Immunity (Federated Sync)

### Concept

Like herd immunity in a population, where widespread vaccination protects even unvaccinated individuals, federated sync allows ShieldX instances to share anonymized pattern intelligence. An attack detected by one deployment strengthens all others.

### Implementation

**Federated Sync** (`src/learning/FederatedSync.ts`): Manages bidirectional sync with the community endpoint.

### What is Shared

| Data | Shared | Format |
|------|--------|--------|
| Attack pattern hash | Yes | SHA-256 of normalized pattern |
| Kill chain phase | Yes | Phase enum value |
| Severity level | Yes | Threat level enum value |
| Scanner type | Yes | Scanner ID that detected it |
| Confidence score | Yes | Anonymized (rounded to 0.1) |
| Pattern category | Yes | Category tag |
| Raw user input | NEVER | Not transmitted |
| Session ID | NEVER | Not transmitted |
| User ID | NEVER | Not transmitted |
| System prompt | NEVER | Not transmitted |
| IP address | NEVER | Not transmitted |
| Conversation context | NEVER | Not transmitted |

### Sync Protocol

1. **Push**: After a pattern is confirmed (via feedback or red team), a sync record is created containing only the hash, phase, severity, and category. This is sent to the community endpoint.

2. **Pull**: Periodically (configurable interval), the instance fetches new community patterns. These are stored with source `'community'` and require local confirmation before they affect detection thresholds.

3. **Conflict Resolution**: If a local pattern conflicts with a community pattern (different severity or phase), the local classification takes precedence. Community patterns serve as additional signals, not overrides.

### Enabling Community Sync

```typescript
const shield = new ShieldX({
  learning: {
    communitySync: true,
    communitySyncUrl: 'https://sync.shieldx.dev/v1/patterns',
  },
})
```

### Characteristics

| Property | Value |
|----------|-------|
| Default state | Disabled (opt-in only) |
| Sync interval | Configurable (default: 1 hour) |
| Data transmitted | Hashes and metadata only |
| Privacy guarantee | No raw input ever leaves the instance |

---

## Supporting Components

### Drift Detector

**Module:** `src/learning/DriftDetector.ts`

Monitors the distribution of detected attack patterns over time. Detects concept drift -- when the nature of attacks changes and existing patterns become less effective.

Drift indicators:
- Rising false negative rate (detected through red team testing)
- Shift in kill chain phase distribution
- New scanner types triggering that previously did not
- Declining confidence scores for existing patterns

When drift is detected, the `DriftReport` triggers:
- Increased red team frequency
- Threshold recalibration
- Active learning sample prioritization
- Alert to operators

### Attack Graph

**Module:** `src/learning/AttackGraph.ts`

Builds a directed graph of attack patterns and their relationships. Nodes represent individual attack patterns. Edges represent observed progressions (e.g., an `initial_access` pattern followed by `privilege_escalation`).

The graph enables:
- Predictive detection: if phase 1 of a known attack chain is detected, pre-emptively guard against the expected phase 2
- Attack campaign identification: correlate related attacks across sessions
- Pattern clustering: identify families of related attack techniques

### Evolution Metrics

The `getStats()` method on the `ShieldX` instance returns `LearningStats`:

```typescript
interface LearningStats {
  totalPatterns: number
  builtinPatterns: number
  learnedPatterns: number
  communityPatterns: number
  redTeamPatterns: number
  totalIncidents: number
  falsePositiveRate: number
  topPatterns: string[]
  recentIncidents: number
  driftDetected: boolean
}
```

These metrics provide visibility into the evolution engine's state and effectiveness.
