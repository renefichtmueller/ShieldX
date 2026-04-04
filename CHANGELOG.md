# Changelog

All notable changes to `@shieldx/core` are documented here.

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
