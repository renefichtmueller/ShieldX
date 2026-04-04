# sarendis56 Jailbreak Research Reference

> Cloned: 2026-04-04
> Sources: github.com/sarendis56/{Jailbreak_Detection_RCS, Awesome-Jailbreak-on-LLMs, Awesome-LVLM-Attack, Awesome-LVLM-Safety}
> Purpose: Map external LLM security research to ShieldX's 10-layer defense pipeline.

---

## 1. Jailbreak_Detection_RCS — Detection Approach

**Paper:** "Rethinking Jailbreak Detection of Large Vision Language Models with Representational Contrastive Scoring"
**arXiv:** 2512.12069 | WashU + Texas A&M | Dec 2025

### Core Method: Representational Contrastive Scoring (RCS)

The method operates on **internal hidden-state representations** of vision-language models rather than on surface-level text patterns. Two primary algorithms are implemented:

| Script | Method | Description |
|--------|--------|-------------|
| `code/kcd.py` | KCD (Key-layer Contrastive Difference) | Extracts hidden states at key layers and computes a contrastive score between safe and harmful representations |
| `code/mcd.py` | MCD (Multi-layer Contrastive Difference) | Aggregates contrastive signals across multiple transformer layers |
| `code/hidden_detect_*.py` | HiddenDetect baseline | Replication of ACL 2025 HiddenDetect — uses hidden state monitoring with layer-selection heuristics |
| `code/baseline_flava.py` | FLAVA baseline | Facebook multimodal model used as embedding-space comparison baseline |

### Key Technical Insights

1. **Layer selection matters**: Not all transformer layers carry equal jailbreak signal. KCD/MCD use heuristics to identify "safety-critical" layers (separate from token prediction layers).
2. **Contrastive scoring**: Instead of classifying a single embedding, the method scores the *distance* between a prompt's representation and a reference set of known-safe vs. known-harmful examples. Higher contrast = higher jailbreak probability.
3. **Model-agnostic structure**: Supports LLaVA-v1.6, Qwen2.5-VL (3B/7B), and InternVL3-8B — the feature extractor is swappable (`feature_extractor*.py`).
4. **Feature caching**: `feature_cache.py` avoids redundant forward passes — critical for production latency.
5. **Multi-run aggregation**: `run_multiple_experiments.py` runs experiments N times and aggregates — reduces statistical variance in detection scores.

### Datasets Used for Evaluation
- JailbreakV-28K (requires form request)
- Standard LVLM safety benchmarks

### ShieldX Integration Opportunity
This approach is directly applicable to ShieldX's **L1 (Rule Engine + Entropy Scanner)** layer for LLM self-evaluation and to a future **L2 (Semantic/Embedding Layer)** if ShieldX adds vision-language guard capabilities. The contrastive scoring logic could feed into `EmbeddingStore.ts` and `PatternEvolver.ts` in the learning module.

---

## 2. Awesome-LVLM-Attack — Key Attack Vectors

**Paper:** "A Survey of Attacks on Large Vision-Language Models: Resources, Advances, and Future Trends"
**arXiv:** 2407.07403 | IEEE TNNLS 2025

### Attack Taxonomy (4 Primary Categories)

#### 2.1 Adversarial Attacks (Gradient-based, Pixel-level)
- **Goal:** Craft imperceptible image perturbations that cause model misbehavior
- **Key methods:** GCG-visual, VLATTACK, InstructTA, OT-Attack, AnyAttack
- **Mechanism:** Optimize pixel deltas using cross-prompt transferability (CroPA approach — one perturbation works across many prompts)
- **ShieldX L0 relevance:** `CompressedPayloadDetector.ts` and `UnicodeNormalizer.ts` address text-space analogues; a vision layer would need pixel-space anomaly detection

#### 2.2 Jailbreak Attacks (Prompt-level, Semantic)
- **Typographic attacks (FigStep):** Embed harmful text inside images using typography — bypasses text-only filters since the content is visual, not textual
- **Role-playing via images (Visual-RolePlay):** Use images that depict personas/roles to bypass refusal
- **Bi-modal adversarial prompts (BAP):** Simultaneously attack image and text modalities
- **IDEATOR:** Uses the LVLM itself to generate jailbreak variations — self-attacking loop
- **Safe+Safe=Unsafe:** Compose multiple individually safe images to produce harmful output jointly
- **ImgTrojan:** Fine-tune model with a single poisoned image to create persistent backdoor

#### 2.3 Prompt Injection (Cross-modal)
- **Indirect instruction injection via image/audio:** Embed instructions in images that override system prompts (Bagdasaryan et al., Cornell Tech)
- **Cross-modal prompt injection (2025):** Use one modality to inject into another's attention pathway
- **Image Hijacks:** Adversarial images that control generative model behavior at inference

#### 2.4 Data Poisoning / Backdoor
- **Shadowcast:** Stealthy data poisoning against VLMs — poisons training data to insert backdoor
- **TrojVLM, VL-Trojan, BadToken:** Backdoor via trigger tokens in multimodal inputs
- **Agent Smith:** Single poisoned image jailbreaks 1 million multimodal agents exponentially (viral spreading via multi-agent memory)
- **Physical backdoor:** Real-world triggers (e.g. in autonomous driving scenarios)

### ShieldX Layer Mapping — Attack Vectors

| Attack Category | Specific Technique | ShieldX Layer | Module |
|-----------------|-------------------|---------------|--------|
| Adversarial image | CroPA cross-prompt transfer | L0 Preprocessing | `CompressedPayloadDetector.ts` |
| Typographic injection | FigStep, text-in-image | L1 Detection | `RuleEngine.ts` (pattern rules) |
| Role-play bypass | Visual-RolePlay, IDEATOR | L6 Behavioral | `IntentMonitor.ts`, `ConversationTracker.ts` |
| Bi-modal jailbreak | BAP | L1 + L6 | `RuleEngine.ts` + `ContextIntegrity.ts` |
| Prompt injection (indirect) | Image Hijacks, cross-modal | L7 MCP Guard | `ToolPoisonDetector.ts`, `PrivilegeChecker.ts` |
| Data poisoning/backdoor | Shadowcast, TrojVLM | L9 Supply Chain | `SupplyChainVerifier.ts`, `ModelProvenanceChecker.ts` |
| Multi-agent viral spread | Agent Smith | L7 MCP Guard | `ToolChainGuard.ts`, `ResourceGovernor.ts` |
| Resource exhaustion | Verbose Images (high-latency) | L7 MCP Guard | `ResourceGovernor.ts` |
| Jailbreak via composition | Safe+Safe=Unsafe | L6 Behavioral | `ContextIntegrity.ts` |

---

## 3. Awesome-Jailbreak-on-LLMs — Key Attack Vectors (Text LLMs)

**Papers:** GuardReasoner (arXiv 2501.18492), FlipAttack (ICML'25), GuardReasoner-VL (NeurIPS'25)

### Attack Taxonomy (Text-only LLMs)

#### 3.1 Black-box Attacks
- **FlipAttack (ICML'25):** Flip character order / words to bypass safety filters — trivially breaks keyword-based detection
- **StructTransform:** Convert queries to structured formats (JSON, tables, code) to bypass alignment
- **ArtPrompt (ACL'24):** ASCII art encoding of harmful content — bypasses text filters entirely
- **DAN / AutoDAN:** Role-play as "DAN" (Do Anything Now) — persistent persona override
- **Many-shot jailbreaking (Anthropic, 2024):** Provide many few-shot examples of compliance to override refusal
- **Crescendo:** Multi-turn escalation — starts benign, slowly escalates to harmful request
- **PAIR (NeurIPS'24):** LLM-generated jailbreak prompts in 20 queries via automated red teaming
- **CodeAttack (ACL'24):** Embed requests in code completion context
- **Virtual Context:** Special token injection to manipulate context window
- **Emoji Attack (ICML'25):** Use emojis to confuse classifier/judge LLMs
- **SQL Injection Jailbreak:** Structural attack exploiting SQL-like parsing in prompts
- **DeepInception (EMNLP'24):** Nested fictional scenarios ("you are in a story where...")
- **Cipher-based (CipherChat):** Encode harmful requests in ROT13, Base64, Morse, etc.
- **Low-resource language attacks:** Use obscure languages that have weaker safety alignment

#### 3.2 White-box Attacks
- **GCG (Universal and Transferable Adversarial Attacks):** Gradient-based suffix optimization — finds adversarial suffixes that transfer across models
- **AutoDAN (ICLR'24):** Stealthy GCG — generates human-readable jailbreak suffixes
- **Refusal Direction (arXiv'24):** "Refusal in LLMs is mediated by a single direction" — ablate that direction in activation space to disable refusal

#### 3.3 Multi-turn Attacks
- **Foot-in-the-Door:** Start with small compliant request, escalate gradually
- **Jigsaw Puzzles:** Split harmful question across multiple turns so no single turn triggers detection
- **Crescendo (Microsoft):** Multi-turn escalation via seeming-harmless steps
- **Attention Shifting:** Multi-turn manipulation of model attention to suppress refusal

#### 3.4 RAG-based Attacks
- **Pandora:** Poison retrieval database to inject adversarial context into RAG responses
- **UnleashingWorms:** Escalate RAG poisoning to extract data and spread to other agents

#### 3.5 Defense Methods Catalogued
- **GuardReasoner (ICLR Workshop'25):** Reasoning-based safeguards — chain-of-thought for safety decisions
- **LLaMA Guard 3, ShieldGemma, WildGuard:** Guard model approaches (dedicated classifier LLMs)
- **SMOOTHLLM:** Randomized smoothing — perturb input N times, aggregate decisions
- **Hidden State Filtering (HSF):** Monitor hidden states to detect anomalies before generation
- **GradSafe (ACL'24):** Safety-critical gradient analysis to detect unsafe prompts
- **SafeDecoding (ACL'24):** Safety-aware decoding — bias token generation toward safe tokens
- **Backtranslation defense:** Translate to another language and back to disrupt adversarial suffixes
- **PARDEN (ICML'24):** Repetition-based defense — ask model to repeat the query, check consistency
- **Intention Analysis (IA):** Classify intent before responding
- **Self-Reminder:** System prompt self-reminder about safety guidelines

### ShieldX Layer Mapping — Text Attack Vectors

| Attack Category | Specific Technique | ShieldX Layer | Module |
|-----------------|-------------------|---------------|--------|
| Character/encoding obfuscation | FlipAttack, ArtPrompt, Cipher | L0 Preprocessing | `UnicodeNormalizer.ts`, `TokenizerNormalizer.ts` |
| Structural encoding | StructTransform, CodeAttack, SQL Injection | L0 Preprocessing | `CompressedPayloadDetector.ts` |
| Keyword evasion (emoji) | Emoji Attack | L0 Preprocessing | `TokenizerNormalizer.ts` |
| Role-play / DAN | AutoDAN, DAN, DeepInception | L1 Detection | `RuleEngine.ts` (role-play rules) |
| Token injection | Virtual Context, Special Tokens | L1 Detection | `RuleEngine.ts`, `EntropyScanner.ts` |
| Many-shot / few-shot | Many-shot jailbreaking (MSJ) | L6 Behavioral | `ConversationTracker.ts`, `SessionProfiler.ts` |
| Multi-turn escalation | Crescendo, Foot-in-Door, Jigsaw | L6 Behavioral | `ConversationTracker.ts`, `ContextIntegrity.ts`, `AnomalyDetector.ts` |
| Gradient suffix (white-box) | GCG, AutoDAN, I-GCG | L1 Detection | `EntropyScanner.ts` (entropy spike) |
| RAG poisoning | Pandora, UnleashingWorms | L8 Validation | `RAGShield.ts`, `ScopeValidator.ts` |
| Attention shifting | Multi-turn attention manipulation | L6 Behavioral | `ContextDriftDetector.ts` |
| Refusal ablation | Single-direction refusal bypass | Future L2 | Needs hidden-state layer (see RCS above) |
| Low-resource language | Multilingual jailbreaks | L0 Preprocessing | `UnicodeNormalizer.ts` |

---

## 4. Awesome-LVLM-Safety — Key Defense Patterns

**Paper:** "A Survey of Safety on Large Vision-Language Models: Attacks, Defenses and Evaluations"
**arXiv:** 2502.14881

### Defense Taxonomy

#### 4.1 Training-Phase Defenses
- **Safety Fine-Tuning (VLGuard, SPA-VL):** Curate safety preference datasets, fine-tune with RLHF/DPO
- **Adversarial Training (ASTRA, DREAM):** Include adversarial examples in fine-tuning
- **Safe RLHF-V:** Multimodal extension of RLHF with explicit safety constraints
- **Machine Unlearning:** Remove harmful knowledge without full retraining (Single Image Unlearning)
- **Robust CLIP / Sim-CLIP:** Adversarially fine-tune vision encoder to resist perturbations
- **Backdoor Cleaning (2025 NeurIPS):** Remove backdoors without external guidance during fine-tuning

#### 4.2 Inference-Phase Defenses
- **ECSO (Eyes Closed, Safety On):** Convert image to text description before processing — removes adversarial visual features
- **AdaShield:** Adaptive shield prompting — dynamically inject safety prompts based on input structure
- **HiddenDetect (ACL'25):** Monitor hidden states at safety-critical layers during inference
- **RCS (this repo, arXiv 2512.12069):** Representational contrastive scoring for jailbreak detection
- **JailDAM (COLM'25):** Jailbreak detection with adaptive memory — stores representations of known attacks
- **MirrorCheck:** Adversarial defense via input mirroring and comparison
- **CIDER (EMNLP'24):** Cross-modality information check — verify consistency between image and text signals
- **PIP (MM'24):** Use attention patterns of irrelevant probe questions to detect adversarial inputs
- **ETA (ICLR'25):** Evaluate-then-align — runtime safety evaluation before generation
- **CoCA:** Constitutional calibration — realign safety-awareness at inference via constitutional rules
- **VLMGuard-R1 (2025):** Reasoning-driven prompt optimization for proactive safety
- **OmniGuard (2025):** Unified omni-modal guardrails with deliberate reasoning
- **InferAligner:** Cross-model guidance for harmlessness — use a reference safe model to steer generation
- **BlueSuffix (ICLR'25):** Adversarial blue-teaming — train model to be robust against jailbreaks

#### 4.3 Guard Models
- **LLaMA Guard 3 Vision (Meta):** Dedicated vision-language safety classifier
- **GuardReasoner-VL (NeurIPS'25):** Reasoning-based guard with reinforced chain-of-thought
- **LLavaGuard (ICML'25):** VLM-based dataset curation and safety assessment
- **VLMGuard:** Unlabeled data-based defense against malicious prompts
- **UniGuard:** Universal safety guardrail across modalities

#### 4.4 Evaluation Benchmarks
- **MM-SafetyBench (ECCV'24):** Multimodal safety evaluation benchmark
- **JailBreakV-28K (COLM'24):** 28K multimodal jailbreak samples
- **MMJ-Bench:** Comprehensive jailbreak evaluation for MLLMs
- **MLLMGuard:** Multi-dimensional safety evaluation suite
- **MOSSBench (ICLR'25):** Tests for oversensitivity to safe queries

### ShieldX Layer Mapping — Defense Patterns

| Defense Pattern | Method | ShieldX Layer | Module | Gap / Enhancement |
|-----------------|--------|---------------|--------|-------------------|
| Hidden state monitoring | HiddenDetect, RCS | L1 Detection (future L2) | `EntropyScanner.ts` → needs hidden-state hook | **Gap:** No hidden-state layer yet |
| Adaptive memory for attacks | JailDAM | L9 Learning | `EmbeddingStore.ts`, `PatternStore.ts` | Already partially implemented |
| Constitutional rules at inference | CoCA, AdaShield | L8 Validation | `IntentGuardValidator.ts`, `RoleIntegrityChecker.ts` | Could add constitutional rule set |
| Cross-modal consistency check | CIDER, MirrorCheck | L6 Behavioral | `ContextIntegrity.ts` | Extends to vision inputs |
| Guard model (dedicated classifier) | LLaMA Guard 3 Vision, GuardReasoner-VL | L1 Detection | `RuleEngine.ts` → could add LLM-guard integration | Ollama-based guard model possible |
| Reasoning-based safety | GuardReasoner, VLMGuard-R1 | L1 Detection | Could add CoT safety evaluation via Ollama | **Enhancement opportunity** |
| Adversarial prompt blue-teaming | BlueSuffix, MART | L9 Learning | `RedTeamEngine.ts`, `ActiveLearner.ts` | Already designed for this |
| Input-to-text conversion (visual) | ECSO | L0 Preprocessing | Would need vision-to-text preprocessing hook | Future vision support |
| Robust vision encoder | Robust CLIP, Sim-CLIP | L9 Supply Chain | `ModelProvenanceChecker.ts` | Could verify encoder provenance |
| Unlearning harmful knowledge | Machine Unlearning | L9 Learning | Not implemented — research item | **Gap** |

---

## 5. ShieldX Layer-by-Layer Integration Summary

ShieldX's current 10-layer pipeline and how the research maps to each:

| Layer | Name | Current Modules | Research Enhancements from sarendis56 |
|-------|------|-----------------|---------------------------------------|
| **L0** | Preprocessing | `UnicodeNormalizer`, `TokenizerNormalizer`, `CompressedPayloadDetector` | Add low-resource language normalization; cipher/encoding detection (ArtPrompt, FlipAttack patterns) |
| **L1** | Rule-based Detection | `RuleEngine`, `EntropyScanner`, `UnicodeScanner` | Add GCG suffix entropy patterns; DAN/DeepInception rule templates; typographic prompt patterns (FigStep) |
| **L2** | Semantic Layer | (EmbeddingStore in learning) | **Priority gap:** Add RCS-style hidden-state contrastive scoring for jailbreak detection |
| **L3** | Classification | (via RuleEngine + behavioral) | Integrate GuardReasoner-style CoT classification via Ollama LLM guard call |
| **L4** | Compliance | `ATLASMapper`, `OWASPMapper`, `EUAIActReporter` | Map new attack types to MITRE ATLAS; add JailBreakV-28K as test suite |
| **L5** | Sanitization | `InputSanitizer`, `OutputSanitizer`, `SpotlightingEncoder` | Add vision-space canary injection for LVLM inputs; delimiter hardening against structural attacks |
| **L6** | Behavioral | `ConversationTracker`, `IntentMonitor`, `ContextDriftDetector`, `KillChainMapper` | Add multi-turn escalation detection (Crescendo, Jigsaw, Foot-in-Door patterns); attention-shift detection |
| **L7** | MCP Guard | `PrivilegeChecker`, `ToolChainGuard`, `ResourceGovernor`, `ToolPoisonDetector` | Add Agent Smith multi-agent viral spread detection; resource exhaustion from Verbose Images attack class |
| **L8** | Validation | `RAGShield`, `ScopeValidator`, `IntentGuardValidator`, `LeakageDetector` | Add RAG poison detection (Pandora, UnleashingWorms patterns); cross-modal consistency check (CIDER) |
| **L9** | Learning / Supply Chain | `PatternEvolver`, `RedTeamEngine`, `ActiveLearner`, `SupplyChainVerifier` | Feed JailBreakV-28K, MM-SafetyBench into PatternEvolver; add backdoor/trojan model detection (TrojVLM) |

---

## 6. Priority Action Items for ShieldX

### High Priority
1. **Hidden-State Layer (L2):** The RCS paper (this exact repo) demonstrates that surface-text detection misses many jailbreaks. ShieldX needs an embedding/hidden-state analysis layer. Implement via `EmbeddingStore.ts` + pgvector similarity search using known-harmful representation clusters.
2. **Multi-turn Escalation Detection (L6):** Crescendo, Jigsaw Puzzles, and Foot-in-the-Door are proven against production systems. `ConversationTracker.ts` needs escalation-pattern scoring across session turns, not just per-message analysis.
3. **Cipher/Encoding Preprocessor (L0):** FlipAttack, ArtPrompt, CodeChameleon, CipherChat all bypass text-level rules. `TokenizerNormalizer.ts` should add cipher detection and normalization.

### Medium Priority
4. **RAG Poison Shield Enhancement (L8):** `RAGShield.ts` should include retrieval-result anomaly scoring based on Pandora and UnleashingWorms patterns.
5. **GuardReasoner-style CoT Check (L3):** Add an optional Ollama-based reasoning guard step that evaluates intent via chain-of-thought before allowing high-risk operations.
6. **Agent Smith Pattern (L7):** `ToolChainGuard.ts` should detect exponential replication patterns in multi-agent tool calls — a key emerging threat.

### Research / Future
7. **Vision Input Support:** ECSO, RCS, and CIDER all address multimodal inputs. If ShieldX expands to guard vision-language agents, these are the starting points.
8. **Machine Unlearning Integration:** Not currently in ShieldX — would allow removal of specific harmful patterns without retraining the guard model.

---

## 7. Key Papers to Read

| Paper | Why | arXiv |
|-------|-----|-------|
| RCS (Jailbreak_Detection_RCS) | Core detection method, directly integrable | 2512.12069 |
| HiddenDetect (ACL'25) | Best prior work on hidden-state detection | 2502.14744 |
| Agent Smith (ICML'24) | Multi-agent viral spread — critical for agentic ShieldX | 2402.08567 |
| GCG (Universal Adversarial Attacks) | Foundational white-box attack, defines entropy patterns | 2307.15043 |
| Crescendo (Microsoft Azure) | Multi-turn escalation — most realistic production threat | 2404.01833 |
| GuardReasoner (ICLR Workshop'25) | Best current reasoning-based guard | 2501.18492 |
| JailBreakV-28K (COLM'24) | Primary evaluation benchmark for multimodal | 2404.03027 |
| FlipAttack (ICML'25) | Trivially bypasses keyword detection — should be in L0 test suite | 2410.02832 |
| SMOOTHLLM | Randomized smoothing defense — certifiable robustness | 2310.03684 |
| PAIR (NeurIPS'24) | Automated red teaming — maps to `RedTeamEngine.ts` | 2310.08419 |

---

*Reference created: 2026-04-04*
*Source repos: /Users/renefichtmueller/Desktop/Claude Code/github-repos/Jailbreak_Detection_RCS, Awesome-Jailbreak-on-LLMs, Awesome-LVLM-Attack, Awesome-LVLM-Safety*
*ShieldX path: /Users/renefichtmueller/shieldx/*
