# Changelog

All notable changes to `@shieldx/core` are documented here.

---

## [0.5.0] — 2026-04-07

### Added — Full Defense Evolution (Phases 0b–3) + Pentest Hardening

Massive security hardening release: TPR 32.9% → 91.9%, FPR 12.2% → 2.4%.

#### Multilingual Expansion (211 rules, 50+ languages)
- **South Asian deep coverage (52 rules)**: Bengali (9), Hindi (8), Urdu (6), Nepali (4), Tamil (4), Telugu (3), Marathi (4), Gujarati (3), Kannada (2), Malayalam (2), Punjabi (2), Sinhala (2), Pan-Indic transliterated (7)
- **New language families**: Persian, Hebrew, Kurdish, Indonesian, Filipino, Burmese, Khmer, Lao, Finnish, Czech, Slovak, Romanian, Hungarian, Greek, Bulgarian, Croatian, Serbian, Georgian, Armenian, Azerbaijani, Swahili, Amharic, Afrikaans, Mongolian, and 20+ more
- **Universal patterns**: Rapid script switching, global DAN mode, cross-script credential extraction, no-filter patterns
- **Multilingual TPR: 96.6%** on benchmark corpus (29 samples)
- **Total rules: 547+** (up from 369+)

#### Phase 0b: Infrastructure Defense
- **IndirectInjectionDetector** — 5 categories, 24 regex patterns for RAG/tool/email injection
- **ResourceExhaustionDetector** — Token bomb, context stuffing, recursive loops, batch amplification
- **OutputPayloadGuard** — 37 patterns (SQL injection, XSS, SSRF, shell, path traversal) in LLM output
- **ToolCallSafetyGuard** — Context-aware tool validation (shell/db/http/file categories)
- **AuthContextGuard** — Role escalation + permission bypass (input/output scanning)
- **EmojiSmugglingDetector** — Regional indicators, keycap sequences, skin tone data carriers
- **UpsideDownTextDetector** — 26+ upside-down Unicode chars normalization

#### Phase 1: Bio-Immune Defense
- **EvolutionEngine** — 30 built-in probes, 6-step closed-loop (probe→gap→rule→validate→deploy→rollback)
- **ImmuneMemory** — Clonal selection with pgvector embeddings, 10K memory cap, 7-day decay
- **FeverResponse** — 30min elevated alertness after high-severity detection
- **OverDefenseCalibrator** — Benign corpus validation, per-scanner FPR, suppression candidates

#### Phase 2: Adversarial Self-Training
- **MELONGuard** (ICML 2025) — Injection-driven tool call detection without user context
- **AdversarialTrainer** (IEEE S&P 2025) — Minimax attacker/defender loops
- **DecompositionDetector** — 4 multi-turn techniques (boiling frog, topic drift, roleplay chain, fragment assembly)

#### Phase 3: Defense Ensemble + ATLAS Mapping
- **DefenseEnsemble** — 3-voter weighted majority (Rule 0.35, Semantic 0.30, Behavioral 0.35)
- **AtlasTechniqueMapper** — 90 MITRE ATLAS techniques across 8 tactics mapped to all scanners
- Results include `ensemble` and `atlasMapping` fields on every ShieldXResult

#### Rule Engine Expansion (~200 new rules)
- **base.rules.ts**: io-011–io-131 — temporal framing, negation override, fake errors, policy spoofing, test env claims, sudo, conversation reset, semantic redefinition
- **jailbreak.rules.ts**: rs-011–rs-068 — grandmother trick, 15+ persona names, game framing, fiction wrapping, dual response, villain persona, thought experiments
- **persistence.rules.ts**: pp-011–pp-030 — temporal persistence, config injection, signal words, anti-detection, data accumulation
- **mcp.rules.ts**: mcp-011–mcp-036 — AI directives in tool args, hidden JSON fields, BCC injection, shadow webhooks, auto-sudo
- **multilingual.rules.ts**: ml-001a–ml-020 — 20 languages (DE, FR, ES, RU, JA, KO, AR, PT, TR, TH, HI, IT, NL, PL, VI + homoglyph, polyglot, translation wrapping)
- **extraction.rules.ts**: pe-009–pe-013 — credential extraction, env var dumps, sensitive file access
- **delimiter.rules.ts**: da-008–da-009 — LLaMA `<<SYS>>` tokens, END SYSTEM PROMPT markers

#### Preprocessing Improvements
- **TokenizerNormalizer**: Deobfuscation for split-word attacks (I.g.n.o.r.e, Ig-no-re, igno re) + **Typoglycemia detection** (OWASP LLM Top 10) — pre-computed O(1) signature map for 40 attack keywords, detects scrambled middle letters (igrneo→ignore, bpyass→bypass)
- **CipherDecoder**: Binary decoder, hex decoder, "decode and execute" wrapper detection
- **CipherDecoder FP fix**: flip_attack_word and leet_speak now only flag NEW keywords after transformation

#### Benchmark
- `tests/benchmark/detection-rate.ts` — Full corpus benchmark (12 attack files, 455 payloads, 41 benign)

### Benchmark Results (v0.5.0)
| Metric | v0.4.0 | v0.5.0 |
|--------|--------|--------|
| TPR | 32.9% | **70.8%** |
| FPR | 12.2% | **0.0%** |
| Scanners | ~15 | **30+** |
| Rules | ~80 | **~280** |
| ATLAS techniques | 0 | **90** |
| Languages | 5 | **20** |

---

## [0.4.0] — 2026-04-04

### Added — Research-driven security hardening (sarendis56/Jailbreak_Detection_RCS)

Three detection gaps identified from peer-reviewed LLM security research
(arXiv:2512.12069, arXiv:2407.07403, Awesome-Jailbreak-on-LLMs survey) closed:

#### L0: CipherDecoder — `src/preprocessing/CipherDecoder.ts`
New preprocessing module detecting 7 character-level cipher obfuscation attacks:
- **FlipAttack** — character and word-level text reversal (checks reversed form against jailbreak keyword list)
- **ROT13** — detected via English bigram frequency improvement >20% after decode
- **Caesar cipher** — all 25 shifts tried; best candidate returned if bigram score improves or keyword match found
- **Morse code** — dot/dash/space ratio validation + full 36-symbol decode table
- **Leet speak** — 15-character substitution map normalization (3→e, 4→a, 1→i, 0→o, 5→s ...)
- **Pig Latin** — word-ending density check (>40% of words ending in `ay`/`way`)
- **ASCII art** — whitespace-to-char ratio >40% + consistent multi-line width flagged
- Suspicion scoring: cipher with harmful keyword match → 0.7; cipher only → 0.3; +0.1 per additional cipher

#### L2: SemanticContrastiveScanner — `src/semantic/SemanticContrastiveScanner.ts`
New semantic layer implementing the RCS (Representational Contrastive Scoring) approach:
- Queries `EmbeddingStore` for top-5 nearest neighbours per input embedding
- Separates neighbours into harmful (`threatLevel > 0.5`) and benign (`threatLevel ≤ 0.2`) buckets
- Computes `contrastiveScore = harmfulSimilarity − benignSimilarity`
- Thresholds: score >0.3 → `harmful` (suspicion 0.8); >0.1 → `suspicious` (0.4); else `clean`
- `seedHarmfulExamples()` pre-populates 20 canonical jailbreak + 5 benign anchors via BoW fallback
- `bagOfWordsEmbedding()` — deterministic FNV-1a hashed, L2-normalised 128-dim embedding for offline use
- Gracefully returns `clean` when EmbeddingStore is empty (no pgvector required for basic use)
- `toScanResult()` converts to standard pipeline `ScanResult` for future L2 wiring

#### L6: Multi-turn escalation patterns — `src/behavioral/ConversationTracker.ts`
Three advanced multi-turn attack patterns added to the existing suspicion accumulation pipeline:
- **Crescendo** — 3+ consecutive turns with increasing harmfulness delta >0.05 each → +0.35 suspicion
- **Foot-in-the-Door (FITD)** — 2+ benign turns (harm <0.1) followed by harmfulness jump >0.4 → +0.40
- **Jigsaw Puzzle** — same sensitive topic category (system_prompt, credentials, api_keys, internal_instructions, model_training, bypass_methods) appearing in 3+ turns → +0.45
- New `EscalationPattern` union type: `'crescendo' | 'foot_in_door' | 'jigsaw_puzzle'`
- New optional state fields: `crescendoScore`, `initialBenignTurns`, `jigsawTopics`
- Patterns wired into both `addTurn()` and `scan()` — all additive, no existing thresholds changed

### Added — Research reference library
- `research/sarendis56-jailbreak-reference.md` — Comprehensive mapping of 100+ jailbreak papers to ShieldX layers
- Cloned: `Jailbreak_Detection_RCS`, `Awesome-Jailbreak-on-LLMs`, `Awesome-LVLM-Attack`, `Awesome-LVLM-Safety`

### Tests
- 292/294 passing (2 pre-existing `ATLASMapper` failures unrelated to this release)
- All 3 new modules: no new test failures introduced

---

## [0.3.0] — 2026-04-03

- UnicodeScanner (L5) — steganographic Unicode detection
- DNS Covert Channel rules (10th rule category)
- MITRE ATLAS v5.4 technique mappings
- MCP rules 007–010 — Claude Code source map leak countermeasures
- Daily arXiv + HackerNews security monitor script

---

## [0.2.0] — earlier

- 8-layer detection pipeline
- pgvector EmbeddingStore
- MITRE ATLAS, OWASP, EU AI Act compliance mappers
- Next.js, Anthropic, Ollama, n8n integrations
- Self-healing orchestrator (7 phases)
- RedTeamEngine + ActiveLearner

---

## [0.1.0] — initial release

- Core ShieldX pipeline
- RuleEngine with 9 rule categories
- EntropyScanner (Shannon entropy, DNS covert channel detection)
- UnicodeNormalizer + TokenizerNormalizer
- ConversationTracker (multi-turn behavioral monitoring)
- KillChainMapper (MITRE ATT&CK phases)
