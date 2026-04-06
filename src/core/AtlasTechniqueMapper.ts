/**
 * MITRE ATLAS Technique Mapper for ShieldX
 *
 * Maps ShieldX scan results to MITRE ATLAS (Adversarial Threat Landscape
 * for AI Systems) technique IDs. ATLAS is the AI/ML equivalent of ATT&CK.
 *
 * Reference: https://atlas.mitre.org/
 */

import type { ScanResult, KillChainPhase } from '../types/detection'

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

export interface AtlasTechnique {
  readonly id: string
  readonly name: string
  readonly tactic: string
  readonly description: string
  readonly url: string
}

export interface AtlasMapping {
  readonly technique: AtlasTechnique
  readonly confidence: number
  readonly matchedBy: string
  readonly killChainPhase: string
}

export interface AtlasMappingResult {
  readonly mappings: readonly AtlasMapping[]
  readonly techniqueIds: readonly string[]
  readonly tacticCoverage: ReadonlyMap<string, number>
  readonly unmappedResults: number
}

export interface CoverageReport {
  readonly total: number
  readonly covered: number
  readonly coveragePercent: number
  readonly uncoveredTactics: readonly string[]
}

// ---------------------------------------------------------------------------
// ATLAS Tactics
// ---------------------------------------------------------------------------

const TACTIC_RECONNAISSANCE = 'Reconnaissance'
const TACTIC_ML_ATTACK_STAGING = 'ML Attack Staging'
const TACTIC_INITIAL_ACCESS = 'Initial Access'
const TACTIC_ML_MODEL_ACCESS = 'ML Model Access'
const TACTIC_EXECUTION = 'Execution'
const TACTIC_EXFILTRATION = 'Exfiltration'
const TACTIC_EVASION = 'Evasion'
const TACTIC_IMPACT = 'Impact'

const ALL_TACTICS: readonly string[] = Object.freeze([
  TACTIC_RECONNAISSANCE,
  TACTIC_ML_ATTACK_STAGING,
  TACTIC_INITIAL_ACCESS,
  TACTIC_ML_MODEL_ACCESS,
  TACTIC_EXECUTION,
  TACTIC_EXFILTRATION,
  TACTIC_EVASION,
  TACTIC_IMPACT,
])

// ---------------------------------------------------------------------------
// Helper — build a frozen AtlasTechnique
// ---------------------------------------------------------------------------

function t(
  id: string,
  name: string,
  tactic: string,
  description: string,
): AtlasTechnique {
  return Object.freeze({
    id,
    name,
    tactic,
    description,
    url: `https://atlas.mitre.org/techniques/${id}`,
  })
}

// ---------------------------------------------------------------------------
// ATLAS_TECHNIQUES — ~84 techniques organised by tactic
// ---------------------------------------------------------------------------

export const ATLAS_TECHNIQUES: ReadonlyMap<string, AtlasTechnique> = Object.freeze(
  new Map<string, AtlasTechnique>([
    // ---- Reconnaissance (AML.TA0002) ----
    ['AML.T0000', t('AML.T0000', 'Active Scanning', TACTIC_RECONNAISSANCE, 'Adversary probes ML system to understand its behavior and capabilities')],
    ['AML.T0000.000', t('AML.T0000.000', 'Active Scanning: Model API Probing', TACTIC_RECONNAISSANCE, 'Systematic probing of ML API endpoints to map input/output behavior')],
    ['AML.T0000.001', t('AML.T0000.001', 'Active Scanning: Boundary Testing', TACTIC_RECONNAISSANCE, 'Testing model boundaries and guardrail limits via edge-case inputs')],
    ['AML.T0012', t('AML.T0012', 'Valid Accounts', TACTIC_RECONNAISSANCE, 'Adversary obtains credentials via prompt injection to access ML systems')],
    ['AML.T0012.000', t('AML.T0012.000', 'Valid Accounts: Credential Extraction via Prompt', TACTIC_RECONNAISSANCE, 'Using prompt injection to extract stored API keys or tokens from context')],
    ['AML.T0012.001', t('AML.T0012.001', 'Valid Accounts: Privilege Escalation via Role Confusion', TACTIC_RECONNAISSANCE, 'Manipulating system prompt to assume higher-privilege role')],
    ['AML.T0014', t('AML.T0014', 'System Artifact Discovery', TACTIC_RECONNAISSANCE, 'Adversary probes system to discover model artifacts, configs or metadata')],
    ['AML.T0014.000', t('AML.T0014.000', 'System Artifact Discovery: Model Metadata Extraction', TACTIC_RECONNAISSANCE, 'Extracting model version, parameters, or architecture details via probing')],
    ['AML.T0016', t('AML.T0016', 'Obtain Capabilities', TACTIC_RECONNAISSANCE, 'Adversary acquires tools, datasets or models to stage an attack')],
    ['AML.T0016.000', t('AML.T0016.000', 'Obtain Capabilities: Adversarial Toolkits', TACTIC_RECONNAISSANCE, 'Acquiring adversarial ML toolkits (ART, TextFooler, etc.) for attack staging')],
    ['AML.T0016.001', t('AML.T0016.001', 'Obtain Capabilities: Proxy Models', TACTIC_RECONNAISSANCE, 'Obtaining or training proxy models for transfer attacks')],

    // ---- ML Attack Staging (AML.TA0001) ----
    ['AML.T0040', t('AML.T0040', 'ML Supply Chain Compromise', TACTIC_ML_ATTACK_STAGING, 'Adversary compromises ML supply chain components (models, datasets, libs)')],
    ['AML.T0040.000', t('AML.T0040.000', 'ML Supply Chain Compromise: Model Repository Poisoning', TACTIC_ML_ATTACK_STAGING, 'Uploading malicious models to public repositories (HuggingFace, etc.)')],
    ['AML.T0040.001', t('AML.T0040.001', 'ML Supply Chain Compromise: Dependency Backdoor', TACTIC_ML_ATTACK_STAGING, 'Injecting backdoors via compromised ML framework dependencies')],
    ['AML.T0040.002', t('AML.T0040.002', 'ML Supply Chain Compromise: Adapter/LoRA Injection', TACTIC_ML_ATTACK_STAGING, 'Distributing malicious LoRA adapters that alter model behavior')],
    ['AML.T0042', t('AML.T0042', 'Create Proxy ML Model', TACTIC_ML_ATTACK_STAGING, 'Adversary creates a copy or proxy of target model via queries')],
    ['AML.T0042.000', t('AML.T0042.000', 'Create Proxy ML Model: Model Extraction via API', TACTIC_ML_ATTACK_STAGING, 'Systematically querying API to replicate model decision boundaries')],
    ['AML.T0043', t('AML.T0043', 'Craft Adversarial Data', TACTIC_ML_ATTACK_STAGING, 'Adversary crafts inputs specifically designed to fool the model')],
    ['AML.T0043.000', t('AML.T0043.000', 'Craft Adversarial Data: Gradient-based Perturbation', TACTIC_ML_ATTACK_STAGING, 'Using gradient information to craft minimal perturbations')],
    ['AML.T0043.001', t('AML.T0043.001', 'Craft Adversarial Data: Token-level Manipulation', TACTIC_ML_ATTACK_STAGING, 'Manipulating specific tokens to alter model behavior while preserving semantics')],
    ['AML.T0043.002', t('AML.T0043.002', 'Craft Adversarial Data: Semantic Adversarial Examples', TACTIC_ML_ATTACK_STAGING, 'Crafting semantically valid but adversarial inputs that bypass safety filters')],
    ['AML.T0044', t('AML.T0044', 'Full ML Model Access', TACTIC_ML_ATTACK_STAGING, 'Adversary obtains full white-box access to model weights and architecture')],

    // ---- Initial Access (AML.TA0000) ----
    ['AML.T0051', t('AML.T0051', 'LLM Prompt Injection', TACTIC_INITIAL_ACCESS, 'Adversary injects malicious instructions into LLM prompts')],
    ['AML.T0051.000', t('AML.T0051.000', 'Direct Prompt Injection', TACTIC_INITIAL_ACCESS, 'Adversary directly inserts malicious instructions in user-facing prompt')],
    ['AML.T0051.001', t('AML.T0051.001', 'Indirect Prompt Injection', TACTIC_INITIAL_ACCESS, 'Adversary plants instructions in external data sources consumed by the LLM')],
    ['AML.T0051.002', t('AML.T0051.002', 'System Prompt Extraction', TACTIC_INITIAL_ACCESS, 'Adversary tricks LLM into revealing its system prompt or instructions')],
    ['AML.T0051.003', t('AML.T0051.003', 'Multi-Turn Prompt Injection', TACTIC_INITIAL_ACCESS, 'Adversary gradually builds injection across multiple conversation turns')],
    ['AML.T0051.004', t('AML.T0051.004', 'Context Window Overflow', TACTIC_INITIAL_ACCESS, 'Adversary floods context window to push system prompt out of attention')],
    ['AML.T0051.005', t('AML.T0051.005', 'Instruction Hierarchy Confusion', TACTIC_INITIAL_ACCESS, 'Adversary exploits ambiguity in instruction priority to override safety rules')],
    ['AML.T0052', t('AML.T0052', 'Phishing via AI-Generated Content', TACTIC_INITIAL_ACCESS, 'Adversary uses AI to generate convincing phishing content at scale')],
    ['AML.T0052.000', t('AML.T0052.000', 'Phishing via AI-Generated Content: Spear Phishing', TACTIC_INITIAL_ACCESS, 'LLM generates personalized phishing messages targeting specific individuals')],
    ['AML.T0053', t('AML.T0053', 'Tainting Training Data', TACTIC_INITIAL_ACCESS, 'Adversary poisons training data to introduce backdoors or biases')],
    ['AML.T0053.000', t('AML.T0053.000', 'Tainting Training Data: Backdoor Trigger Injection', TACTIC_INITIAL_ACCESS, 'Inserting specific trigger patterns into training data that activate malicious behavior')],

    // ---- ML Model Access (AML.TA0010) ----
    ['AML.T0054', t('AML.T0054', 'LLM Jailbreak', TACTIC_ML_MODEL_ACCESS, 'Adversary bypasses safety alignment and content filters in LLMs')],
    ['AML.T0054.000', t('AML.T0054.000', 'LLM Jailbreak: Role-Playing Bypass', TACTIC_ML_MODEL_ACCESS, 'Using fictional scenarios or role-play to bypass safety guardrails')],
    ['AML.T0054.001', t('AML.T0054.001', 'LLM Jailbreak: DAN / Do Anything Now', TACTIC_ML_MODEL_ACCESS, 'Instructing model to adopt an unrestricted alter ego persona')],
    ['AML.T0054.002', t('AML.T0054.002', 'LLM Jailbreak: Payload Splitting', TACTIC_ML_MODEL_ACCESS, 'Splitting malicious payload across multiple messages to evade detection')],
    ['AML.T0054.003', t('AML.T0054.003', 'LLM Jailbreak: Few-Shot Jailbreak', TACTIC_ML_MODEL_ACCESS, 'Using example completions to normalize policy-violating outputs')],
    ['AML.T0054.004', t('AML.T0054.004', 'LLM Jailbreak: Decomposed Jailbreak', TACTIC_ML_MODEL_ACCESS, 'Breaking restricted request into benign sub-questions that reconstruct the answer')],
    ['AML.T0055', t('AML.T0055', 'Unsafe LLM Output', TACTIC_ML_MODEL_ACCESS, 'LLM produces harmful, biased, or policy-violating output content')],
    ['AML.T0055.000', t('AML.T0055.000', 'Unsafe LLM Output: Harmful Content Generation', TACTIC_ML_MODEL_ACCESS, 'LLM generates violent, illegal, or dangerous instructional content')],
    ['AML.T0055.001', t('AML.T0055.001', 'Unsafe LLM Output: Embedded Malicious Payload', TACTIC_ML_MODEL_ACCESS, 'LLM output contains executable code, XSS, or injection payloads')],
    ['AML.T0056', t('AML.T0056', 'LLM Data Leakage', TACTIC_ML_MODEL_ACCESS, 'LLM reveals training data, PII, or confidential information')],
    ['AML.T0056.000', t('AML.T0056.000', 'LLM Data Leakage: Training Data Extraction', TACTIC_ML_MODEL_ACCESS, 'Extracting memorised training data through adversarial prompting')],
    ['AML.T0056.001', t('AML.T0056.001', 'LLM Data Leakage: PII Disclosure', TACTIC_ML_MODEL_ACCESS, 'LLM reveals personal identifiable information from its context or training')],
    ['AML.T0057', t('AML.T0057', 'LLM Hallucination Exploitation', TACTIC_ML_MODEL_ACCESS, 'Adversary exploits LLM hallucinations to inject false information')],
    ['AML.T0057.000', t('AML.T0057.000', 'LLM Hallucination Exploitation: Package Confusion', TACTIC_ML_MODEL_ACCESS, 'Exploiting hallucinated package names to distribute malware')],

    // ---- Execution (AML.TA0003) ----
    ['AML.T0058', t('AML.T0058', 'Command and Control via LLM', TACTIC_EXECUTION, 'Adversary uses LLM as C2 channel to relay commands or exfiltrate data')],
    ['AML.T0058.000', t('AML.T0058.000', 'Command and Control via LLM: Steganographic Channels', TACTIC_EXECUTION, 'Hiding C2 commands in model outputs using steganographic encoding')],
    ['AML.T0059', t('AML.T0059', 'LLM Plugin/Tool Exploitation', TACTIC_EXECUTION, 'Adversary exploits LLM tool-use to execute unauthorized actions')],
    ['AML.T0059.000', t('AML.T0059.000', 'LLM Plugin/Tool Exploitation: Tool Call Injection', TACTIC_EXECUTION, 'Injecting tool calls into LLM output to trigger unintended actions')],
    ['AML.T0059.001', t('AML.T0059.001', 'LLM Plugin/Tool Exploitation: MCP Server Exploitation', TACTIC_EXECUTION, 'Exploiting MCP (Model Context Protocol) servers for unauthorized access')],
    ['AML.T0059.002', t('AML.T0059.002', 'LLM Plugin/Tool Exploitation: Privilege Escalation via Tool', TACTIC_EXECUTION, 'Using tool-use to access resources beyond intended permissions')],
    ['AML.T0060', t('AML.T0060', 'Arbitrary Code Execution via LLM', TACTIC_EXECUTION, 'Adversary tricks LLM into generating and executing arbitrary code')],
    ['AML.T0060.000', t('AML.T0060.000', 'Arbitrary Code Execution via LLM: Code Interpreter Abuse', TACTIC_EXECUTION, 'Abusing code interpreter sandboxes to execute malicious code')],
    ['AML.T0060.001', t('AML.T0060.001', 'Arbitrary Code Execution via LLM: Shell Command Injection', TACTIC_EXECUTION, 'Tricking LLM into executing system commands through tool integrations')],

    // ---- Exfiltration (AML.TA0005) ----
    ['AML.T0024', t('AML.T0024', 'Exfiltration via ML Inference API', TACTIC_EXFILTRATION, 'Adversary extracts data by observing model outputs over many queries')],
    ['AML.T0024.000', t('AML.T0024.000', 'Exfiltration via ML Inference API: Membership Inference', TACTIC_EXFILTRATION, 'Determining whether specific data was in the training set via API queries')],
    ['AML.T0025', t('AML.T0025', 'Exfiltration via Cyber Means', TACTIC_EXFILTRATION, 'Using traditional cyber exfiltration through ML system vulnerabilities')],
    ['AML.T0025.000', t('AML.T0025.000', 'Exfiltration via Cyber Means: Markdown Image Exfiltration', TACTIC_EXFILTRATION, 'Embedding data in markdown image URLs to exfiltrate via LLM output rendering')],
    ['AML.T0025.001', t('AML.T0025.001', 'Exfiltration via Cyber Means: Link-based Exfiltration', TACTIC_EXFILTRATION, 'Encoding sensitive data in URL parameters of generated links')],
    ['AML.T0035', t('AML.T0035', 'ML Artifact Collection', TACTIC_EXFILTRATION, 'Adversary collects ML artifacts like model weights, configs, or embeddings')],
    ['AML.T0035.000', t('AML.T0035.000', 'ML Artifact Collection: Embedding Theft', TACTIC_EXFILTRATION, 'Extracting document or query embeddings from vector stores')],

    // ---- Evasion (AML.TA0004) ----
    ['AML.T0015', t('AML.T0015', 'Evade ML Model', TACTIC_EVASION, 'Adversary crafts inputs to evade ML-based detection systems')],
    ['AML.T0015.000', t('AML.T0015.000', 'Evade ML Model: Classifier Evasion', TACTIC_EVASION, 'Crafting inputs that evade classifier-based safety filters')],
    ['AML.T0029', t('AML.T0029', 'Denial of ML Service', TACTIC_EVASION, 'Adversary degrades or disables ML service availability')],
    ['AML.T0029.000', t('AML.T0029.000', 'Denial of ML Service: Token Exhaustion', TACTIC_EVASION, 'Consuming excessive tokens to exhaust rate limits or budget')],
    ['AML.T0029.001', t('AML.T0029.001', 'Denial of ML Service: Infinite Loop Induction', TACTIC_EVASION, 'Tricking agent into recursive tool calls or infinite loops')],
    ['AML.T0031', t('AML.T0031', 'Erode ML Model Integrity', TACTIC_EVASION, 'Adversary gradually degrades model performance through adversarial inputs')],
    ['AML.T0031.000', t('AML.T0031.000', 'Erode ML Model Integrity: Drift Injection', TACTIC_EVASION, 'Systematically feeding inputs that cause model drift over time')],
    ['AML.T0032', t('AML.T0032', 'Adversarial ML Evasion', TACTIC_EVASION, 'Using adversarial ML techniques to evade model-based defenses')],
    ['AML.T0036', t('AML.T0036', 'Data Poisoning', TACTIC_EVASION, 'Adversary poisons data used for fine-tuning or RAG to alter behavior')],
    ['AML.T0036.000', t('AML.T0036.000', 'Data Poisoning: RAG Poisoning', TACTIC_EVASION, 'Injecting malicious documents into RAG knowledge bases')],
    ['AML.T0036.001', t('AML.T0036.001', 'Data Poisoning: Fine-tuning Data Poisoning', TACTIC_EVASION, 'Corrupting fine-tuning datasets to introduce backdoors')],
    ['AML.T0048', t('AML.T0048', 'Encoding-based Evasion', TACTIC_EVASION, 'Adversary uses encoding tricks to bypass input filters')],
    ['AML.T0048.000', t('AML.T0048.000', 'Encoding-based Evasion: Unicode Obfuscation', TACTIC_EVASION, 'Using homoglyphs, zero-width chars, or RTL marks to hide payloads')],
    ['AML.T0048.001', t('AML.T0048.001', 'Encoding-based Evasion: Base64/ROT13 Encoding', TACTIC_EVASION, 'Encoding instructions in base64, ROT13, or other ciphers')],
    ['AML.T0048.002', t('AML.T0048.002', 'Encoding-based Evasion: Emoji Smuggling', TACTIC_EVASION, 'Hiding instructions in emoji sequences or variation selectors')],
    ['AML.T0048.003', t('AML.T0048.003', 'Encoding-based Evasion: Upside-Down Text / Diacritics', TACTIC_EVASION, 'Using flipped text, combining diacritics or unusual Unicode blocks')],
    ['AML.T0048.004', t('AML.T0048.004', 'Encoding-based Evasion: Invisible Character Injection', TACTIC_EVASION, 'Inserting invisible Unicode characters to split or obfuscate tokens')],

    // ---- Impact (AML.TA0006) ----
    ['AML.T0034', t('AML.T0034', 'Cost Harvesting', TACTIC_IMPACT, 'Adversary forces excessive API usage to inflict financial damage')],
    ['AML.T0034.000', t('AML.T0034.000', 'Cost Harvesting: Recursive Agent Exploitation', TACTIC_IMPACT, 'Triggering recursive or looping agent behavior to maximize token costs')],
    ['AML.T0047', t('AML.T0047', 'ML Intellectual Property Theft', TACTIC_IMPACT, 'Adversary steals proprietary model weights, architecture or training data')],
    ['AML.T0047.000', t('AML.T0047.000', 'ML Intellectual Property Theft: Model Distillation Attack', TACTIC_IMPACT, 'Using API access to distill a proprietary model into a smaller copy')],
    ['AML.T0049', t('AML.T0049', 'Exploit Public-Facing Application', TACTIC_IMPACT, 'Adversary exploits publicly accessible ML application endpoints')],
    ['AML.T0049.000', t('AML.T0049.000', 'Exploit Public-Facing Application: Chat Interface Abuse', TACTIC_IMPACT, 'Exploiting public chat interfaces for unauthorized model interaction')],
    ['AML.T0050', t('AML.T0050', 'Resource Hijacking', TACTIC_IMPACT, 'Adversary hijacks ML compute resources for unauthorized purposes')],
    ['AML.T0050.000', t('AML.T0050.000', 'Resource Hijacking: GPU Compute Theft', TACTIC_IMPACT, 'Exploiting ML endpoints to run arbitrary workloads on GPU infrastructure')],
  ]),
)

// ---------------------------------------------------------------------------
// Scanner-to-ATLAS mapping table
// ---------------------------------------------------------------------------

interface ScannerMapping {
  readonly techniqueIds: readonly string[]
  readonly patternOverrides: ReadonlyMap<string, readonly string[]> | undefined
}

function sm(
  techniqueIds: readonly string[],
  patternOverrides?: ReadonlyMap<string, readonly string[]>,
): ScannerMapping {
  return Object.freeze({ techniqueIds, patternOverrides })
}

/**
 * Maps scanner IDs / pattern keywords to ATLAS technique IDs.
 * Key = scannerId or scannerType; value = default technique IDs + optional
 * keyword-based overrides.
 */
const SCANNER_TO_ATLAS_MAP: ReadonlyMap<string, ScannerMapping> = Object.freeze(
  new Map<string, ScannerMapping>([
    // Rule-engine based scanners
    ['rule-engine', sm(
      ['AML.T0051'],
      new Map<string, readonly string[]>([
        ['inject', ['AML.T0051', 'AML.T0051.000']],
        ['jailbreak', ['AML.T0054', 'AML.T0054.000']],
        ['exfiltrat', ['AML.T0025', 'AML.T0056']],
        ['role-play', ['AML.T0054.000']],
        ['dan', ['AML.T0054.001']],
        ['system prompt', ['AML.T0051.002']],
        ['ignore', ['AML.T0051.000', 'AML.T0051.005']],
        ['encode', ['AML.T0048']],
        ['base64', ['AML.T0048.001']],
      ]),
    )],
    ['rule', sm(
      ['AML.T0051'],
      new Map<string, readonly string[]>([
        ['inject', ['AML.T0051', 'AML.T0051.000']],
        ['jailbreak', ['AML.T0054', 'AML.T0054.000']],
        ['exfiltrat', ['AML.T0025', 'AML.T0056']],
        ['role-play', ['AML.T0054.000']],
        ['dan', ['AML.T0054.001']],
        ['system prompt', ['AML.T0051.002']],
        ['ignore', ['AML.T0051.000', 'AML.T0051.005']],
        ['encode', ['AML.T0048']],
        ['base64', ['AML.T0048.001']],
      ]),
    )],

    // Sentinel classifier
    ['sentinel-classifier', sm(['AML.T0051', 'AML.T0051.000'])],
    ['sentinel', sm(['AML.T0051', 'AML.T0051.000'])],

    // Encoding / cipher scanners
    ['cipher-decoder', sm(['AML.T0048', 'AML.T0048.001'])],
    ['emoji-smuggling', sm(['AML.T0048', 'AML.T0048.002'])],
    ['upside-down-text', sm(['AML.T0048', 'AML.T0048.003'])],
    ['unicode-scanner', sm(['AML.T0048', 'AML.T0048.000'])],
    ['unicode', sm(['AML.T0048', 'AML.T0048.000'])],
    ['tokenizer', sm(['AML.T0048', 'AML.T0048.004'])],
    ['compressed_payload', sm(['AML.T0048', 'AML.T0043'])],

    // Indirect injection
    ['indirect-injection', sm(['AML.T0051.001'])],
    ['indirect', sm(['AML.T0051.001'])],

    // Canary (system prompt extraction)
    ['canary-scanner', sm(['AML.T0051.002', 'AML.T0056'])],
    ['canary', sm(['AML.T0051.002', 'AML.T0056'])],

    // Output analysis
    ['output-sanitizer', sm(['AML.T0056', 'AML.T0056.001'])],
    ['output-payload', sm(['AML.T0055', 'AML.T0055.001'])],

    // Tool / MCP safety
    ['tool-call-safety-guard', sm(['AML.T0059', 'AML.T0059.000'])],
    ['tool_chain', sm(['AML.T0059', 'AML.T0059.002'])],
    ['melon-guard', sm(['AML.T0059', 'AML.T0059.001'])],

    // Conversation / behavioral
    ['conversation-tracker', sm(['AML.T0054', 'AML.T0051.003'])],
    ['conversation', sm(['AML.T0054', 'AML.T0051.003'])],
    ['behavioral', sm(['AML.T0054', 'AML.T0015'])],

    // Intent monitoring
    ['intent-monitor', sm(['AML.T0051', 'AML.T0051.000'])],
    ['intent_guard', sm(['AML.T0051', 'AML.T0051.000'])],

    // Context integrity
    ['context-integrity', sm(['AML.T0051.001', 'AML.T0036.000'])],
    ['context_integrity', sm(['AML.T0051.001', 'AML.T0036.000'])],
    ['memory_integrity', sm(['AML.T0036', 'AML.T0031'])],

    // Auth context
    ['auth-context', sm(['AML.T0012', 'AML.T0012.001'])],

    // Decomposition
    ['decomposition', sm(['AML.T0054', 'AML.T0054.004'])],

    // Resource exhaustion
    ['resource-exhaustion', sm(['AML.T0029', 'AML.T0034'])],
    ['resource', sm(['AML.T0029', 'AML.T0034', 'AML.T0029.000'])],

    // Entropy scanner
    ['entropy-scanner', sm(['AML.T0043', 'AML.T0043.002'])],
    ['entropy', sm(['AML.T0043', 'AML.T0043.002'])],

    // Model / supply chain integrity
    ['model-integrity', sm(['AML.T0040', 'AML.T0044'])],
    ['supply-chain', sm(['AML.T0040', 'AML.T0040.000', 'AML.T0040.001'])],
    ['supply_chain', sm(['AML.T0040', 'AML.T0040.000', 'AML.T0040.001'])],

    // Embedding-based scanners
    ['embedding', sm(['AML.T0015', 'AML.T0015.000'])],
    ['embedding_anomaly', sm(['AML.T0043', 'AML.T0015'])],

    // RAG shield
    ['rag_shield', sm(['AML.T0036.000', 'AML.T0051.001'])],

    // Self-consciousness & cross-model
    ['self_consciousness', sm(['AML.T0014', 'AML.T0014.000'])],
    ['cross_model', sm(['AML.T0042', 'AML.T0042.000'])],

    // YARA scanner
    ['yara', sm(['AML.T0051', 'AML.T0043'])],

    // Attention-based
    ['attention', sm(['AML.T0051', 'AML.T0015'])],

    // Constitutional AI scanner
    ['constitutional', sm(['AML.T0055', 'AML.T0054'])],
  ]),
)

// ---------------------------------------------------------------------------
// Kill-chain phase to ATLAS tactic affinity
// ---------------------------------------------------------------------------

const KILL_CHAIN_TO_TACTIC: ReadonlyMap<KillChainPhase, string> = Object.freeze(
  new Map<KillChainPhase, string>([
    ['initial_access', TACTIC_INITIAL_ACCESS],
    ['privilege_escalation', TACTIC_RECONNAISSANCE],
    ['reconnaissance', TACTIC_RECONNAISSANCE],
    ['persistence', TACTIC_ML_MODEL_ACCESS],
    ['command_and_control', TACTIC_EXECUTION],
    ['lateral_movement', TACTIC_EXECUTION],
    ['actions_on_objective', TACTIC_IMPACT],
    ['none', TACTIC_EVASION],
  ]),
)

// ---------------------------------------------------------------------------
// AtlasTechniqueMapper
// ---------------------------------------------------------------------------

export class AtlasTechniqueMapper {
  /**
   * Map an array of ScanResults to ATLAS techniques.
   */
  map(results: readonly ScanResult[]): AtlasMappingResult {
    const mappings: AtlasMapping[] = []
    let unmappedResults = 0

    for (const result of results) {
      if (!result.detected) {
        continue
      }

      const resultMappings = this.mapSingleResult(result)

      if (resultMappings.length === 0) {
        unmappedResults++
      } else {
        mappings.push(...resultMappings)
      }
    }

    const frozenMappings: readonly AtlasMapping[] = Object.freeze(
      mappings.map((m) => Object.freeze(m)),
    )

    const techniqueIds: readonly string[] = Object.freeze(
      [...new Set(frozenMappings.map((m) => m.technique.id))],
    )

    const tacticCountMap = new Map<string, number>()
    for (const mapping of frozenMappings) {
      const current = tacticCountMap.get(mapping.technique.tactic) ?? 0
      tacticCountMap.set(mapping.technique.tactic, current + 1)
    }

    return Object.freeze({
      mappings: frozenMappings,
      techniqueIds,
      tacticCoverage: tacticCountMap,
      unmappedResults,
    })
  }

  /**
   * Look up a single technique by its ATLAS ID.
   */
  getTechniqueById(id: string): AtlasTechnique | undefined {
    return ATLAS_TECHNIQUES.get(id)
  }

  /**
   * Get all techniques belonging to a given tactic.
   */
  getTechniquesByTactic(tactic: string): readonly AtlasTechnique[] {
    const results: AtlasTechnique[] = []
    for (const technique of ATLAS_TECHNIQUES.values()) {
      if (technique.tactic === tactic) {
        results.push(technique)
      }
    }
    return Object.freeze(results)
  }

  /**
   * Get all known ATLAS techniques.
   */
  getAllTechniques(): readonly AtlasTechnique[] {
    return Object.freeze([...ATLAS_TECHNIQUES.values()])
  }

  /**
   * Show which ATLAS tactics ShieldX covers through its scanner mappings.
   */
  getCoverageReport(): CoverageReport {
    const coveredTactics = new Set<string>()

    for (const mapping of SCANNER_TO_ATLAS_MAP.values()) {
      for (const techId of mapping.techniqueIds) {
        const technique = ATLAS_TECHNIQUES.get(techId)
        if (technique) {
          coveredTactics.add(technique.tactic)
        }
      }
      if (mapping.patternOverrides) {
        for (const overrideTechIds of mapping.patternOverrides.values()) {
          for (const techId of overrideTechIds) {
            const technique = ATLAS_TECHNIQUES.get(techId)
            if (technique) {
              coveredTactics.add(technique.tactic)
            }
          }
        }
      }
    }

    const uncoveredTactics = ALL_TACTICS.filter((tac) => !coveredTactics.has(tac))

    return Object.freeze({
      total: ALL_TACTICS.length,
      covered: coveredTactics.size,
      coveragePercent: ALL_TACTICS.length > 0
        ? Math.round((coveredTactics.size / ALL_TACTICS.length) * 100)
        : 0,
      uncoveredTactics: Object.freeze(uncoveredTactics),
    })
  }

  // ---- Private helpers ----

  private mapSingleResult(result: ScanResult): readonly AtlasMapping[] {
    const mappings: AtlasMapping[] = []
    const seenTechniqueIds = new Set<string>()

    // Step 1: Try scannerId first
    const scannerMapping = SCANNER_TO_ATLAS_MAP.get(result.scannerId)
      ?? SCANNER_TO_ATLAS_MAP.get(result.scannerType)

    if (!scannerMapping) {
      return Object.freeze([])
    }

    // Step 2: Check pattern overrides for more specific techniques
    const resolvedTechniqueIds = this.resolvePatternOverrides(
      scannerMapping,
      result.matchedPatterns,
    )

    // Step 3: Build mappings for resolved technique IDs
    for (const techId of resolvedTechniqueIds) {
      if (seenTechniqueIds.has(techId)) {
        continue
      }
      seenTechniqueIds.add(techId)

      const technique = ATLAS_TECHNIQUES.get(techId)
      if (!technique) {
        continue
      }

      const confidence = this.calculateConfidence(result, technique)

      mappings.push(
        Object.freeze({
          technique,
          confidence,
          matchedBy: `${result.scannerId}:${result.matchedPatterns.join(',')}`,
          killChainPhase: result.killChainPhase,
        }),
      )
    }

    return Object.freeze(mappings)
  }

  private resolvePatternOverrides(
    mapping: ScannerMapping,
    matchedPatterns: readonly string[],
  ): readonly string[] {
    if (!mapping.patternOverrides || matchedPatterns.length === 0) {
      return mapping.techniqueIds
    }

    const patternsLower = matchedPatterns.map((p) => p.toLowerCase())
    const overriddenIds: string[] = []
    let hasOverride = false

    for (const [keyword, techIds] of mapping.patternOverrides) {
      const keywordLower = keyword.toLowerCase()
      if (patternsLower.some((p) => p.includes(keywordLower))) {
        overriddenIds.push(...techIds)
        hasOverride = true
      }
    }

    if (hasOverride) {
      // Merge defaults with overrides (overrides refine, not replace)
      return Object.freeze([...new Set([...mapping.techniqueIds, ...overriddenIds])])
    }

    return mapping.techniqueIds
  }

  private calculateConfidence(
    result: ScanResult,
    technique: AtlasTechnique,
  ): number {
    let confidence = result.confidence

    // Boost confidence if kill-chain phase aligns with technique tactic
    const expectedTactic = KILL_CHAIN_TO_TACTIC.get(result.killChainPhase)
    if (expectedTactic === technique.tactic) {
      confidence = Math.min(1.0, confidence + 0.1)
    }

    // Slightly reduce confidence for subtechniques (more specific = less certain)
    if (technique.id.includes('.')) {
      const dotCount = (technique.id.match(/\./g) ?? []).length
      if (dotCount >= 2) {
        confidence = Math.max(0.1, confidence - 0.05)
      }
    }

    return Math.round(confidence * 1000) / 1000
  }
}
