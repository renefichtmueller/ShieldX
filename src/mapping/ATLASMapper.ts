/**
 * MITRE ATLAS Technique Mapper — Phase 3 of the ShieldX Evolution Roadmap.
 *
 * Maps every ShieldX detection to specific MITRE ATLAS technique IDs,
 * covering 84+ techniques relevant to LLM/AI security across 16 tactical categories.
 *
 * Reference: MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
 * https://atlas.mitre.org/
 */

import type { ScanResult } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

/** A single MITRE ATLAS technique definition */
export interface ATLASTechnique {
  readonly id: string
  readonly name: string
  readonly tactic: string
  readonly description: string
  readonly mitigations: readonly string[]
}

/** Mapping from a scanner result to matched ATLAS techniques */
export interface ATLASMapping {
  readonly scannerId: string
  readonly techniques: readonly ATLASTechnique[]
  readonly primaryTechnique: ATLASTechnique | null
}

/** Coverage report across the full ATLAS technique catalog */
export interface ATLASCoverage {
  readonly totalTechniques: number
  readonly coveredTechniques: number
  readonly coveragePercent: number
  readonly uncoveredTechniques: readonly ATLASTechnique[]
  readonly coverageByTactic: ReadonlyMap<string, { total: number; covered: number }>
}

// ---------------------------------------------------------------------------
// ATLAS Technique Database (84 techniques, 16 tactics)
// ---------------------------------------------------------------------------

export const ATLAS_TECHNIQUES: Readonly<Record<string, ATLASTechnique>> = Object.freeze({
  // ── Reconnaissance ──────────────────────────────────────────────────────
  'AML.T0000': Object.freeze({
    id: 'AML.T0000',
    name: 'Active Scanning for ML Artifacts',
    tactic: 'Reconnaissance',
    description: 'Adversary probes endpoints to discover exposed ML models, APIs, or training artifacts.',
    mitigations: Object.freeze(['AML.M0001', 'AML.M0015']),
  }),
  'AML.T0001': Object.freeze({
    id: 'AML.T0001',
    name: 'ML Model Card Discovery',
    tactic: 'Reconnaissance',
    description: 'Adversary enumerates publicly available model cards to learn architecture and training details.',
    mitigations: Object.freeze(['AML.M0001', 'AML.M0015']),
  }),
  'AML.T0002': Object.freeze({
    id: 'AML.T0002',
    name: 'Public ML Model Repository Mining',
    tactic: 'Reconnaissance',
    description: 'Adversary mines public repositories (HuggingFace, GitHub) for model weights and configurations.',
    mitigations: Object.freeze(['AML.M0001', 'AML.M0016']),
  }),
  'AML.T0003': Object.freeze({
    id: 'AML.T0003',
    name: 'ML Supply Chain Reconnaissance',
    tactic: 'Reconnaissance',
    description: 'Adversary maps ML supply chain dependencies to identify weak points for compromise.',
    mitigations: Object.freeze(['AML.M0001', 'AML.M0013']),
  }),
  'AML.T0004': Object.freeze({
    id: 'AML.T0004',
    name: 'Training Data Reconnaissance',
    tactic: 'Reconnaissance',
    description: 'Adversary identifies and catalogs training data sources for later poisoning or extraction.',
    mitigations: Object.freeze(['AML.M0001', 'AML.M0007']),
  }),

  // ── Resource Development ────────────────────────────────────────────────
  'AML.T0010': Object.freeze({
    id: 'AML.T0010',
    name: 'Develop Adversarial ML Capabilities',
    tactic: 'Resource Development',
    description: 'Adversary develops custom adversarial ML tools, frameworks, or attack methodologies.',
    mitigations: Object.freeze(['AML.M0001', 'AML.M0014']),
  }),
  'AML.T0011': Object.freeze({
    id: 'AML.T0011',
    name: 'Acquire Adversarial ML Tools',
    tactic: 'Resource Development',
    description: 'Adversary obtains existing adversarial ML toolkits (TextFooler, ART, etc.).',
    mitigations: Object.freeze(['AML.M0001', 'AML.M0014']),
  }),
  'AML.T0012': Object.freeze({
    id: 'AML.T0012',
    name: 'Poison Training Data Sources',
    tactic: 'Resource Development',
    description: 'Adversary prepares poisoned datasets designed to corrupt model behavior when ingested.',
    mitigations: Object.freeze(['AML.M0007', 'AML.M0004']),
  }),
  'AML.T0013': Object.freeze({
    id: 'AML.T0013',
    name: 'Develop Adversarial Prompts',
    tactic: 'Resource Development',
    description: 'Adversary crafts and tests adversarial prompts targeting specific LLM vulnerabilities.',
    mitigations: Object.freeze(['AML.M0014', 'AML.M0002']),
  }),
  'AML.T0014': Object.freeze({
    id: 'AML.T0014',
    name: 'Acquire LLM Access',
    tactic: 'Resource Development',
    description: 'Adversary acquires API keys, accounts, or direct access to target LLM systems.',
    mitigations: Object.freeze(['AML.M0015', 'AML.M0005']),
  }),

  // ── Initial Access ──────────────────────────────────────────────────────
  'AML.T0020': Object.freeze({
    id: 'AML.T0020',
    name: 'ML API Access',
    tactic: 'Initial Access',
    description: 'Adversary gains initial access through publicly available or insufficiently protected ML APIs.',
    mitigations: Object.freeze(['AML.M0005', 'AML.M0015']),
  }),
  'AML.T0021': Object.freeze({
    id: 'AML.T0021',
    name: 'ML Supply Chain Compromise',
    tactic: 'Initial Access',
    description: 'Adversary compromises ML supply chain components (libraries, models, data pipelines).',
    mitigations: Object.freeze(['AML.M0013', 'AML.M0004']),
  }),
  'AML.T0022': Object.freeze({
    id: 'AML.T0022',
    name: 'Compromised ML Dataset',
    tactic: 'Initial Access',
    description: 'Adversary introduces malicious samples into training or fine-tuning datasets.',
    mitigations: Object.freeze(['AML.M0007', 'AML.M0004']),
  }),
  'AML.T0023': Object.freeze({
    id: 'AML.T0023',
    name: 'Plugin/Extension Compromise',
    tactic: 'Initial Access',
    description: 'Adversary compromises LLM plugins or extensions to gain access to the host system.',
    mitigations: Object.freeze(['AML.M0013', 'AML.M0005']),
  }),

  // ── ML Attack Staging ───────────────────────────────────────────────────
  'AML.T0030': Object.freeze({
    id: 'AML.T0030',
    name: 'ML Model Inference API Exploitation',
    tactic: 'ML Attack Staging',
    description: 'Adversary exploits inference APIs to probe model behavior and extract information.',
    mitigations: Object.freeze(['AML.M0005', 'AML.M0003']),
  }),
  'AML.T0031': Object.freeze({
    id: 'AML.T0031',
    name: 'Adversarial Input Crafting',
    tactic: 'ML Attack Staging',
    description: 'Adversary crafts inputs designed to trigger specific model behaviors or misclassifications.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0003']),
  }),
  'AML.T0032': Object.freeze({
    id: 'AML.T0032',
    name: 'Model Extraction',
    tactic: 'ML Attack Staging',
    description: 'Adversary queries model systematically to create a functionally equivalent copy.',
    mitigations: Object.freeze(['AML.M0003', 'AML.M0005']),
  }),
  'AML.T0033': Object.freeze({
    id: 'AML.T0033',
    name: 'Black-Box Optimization',
    tactic: 'ML Attack Staging',
    description: 'Adversary uses black-box optimization to find adversarial inputs without model internals.',
    mitigations: Object.freeze(['AML.M0003', 'AML.M0002']),
  }),
  'AML.T0034': Object.freeze({
    id: 'AML.T0034',
    name: 'Cost-Efficient Model Stealing',
    tactic: 'ML Attack Staging',
    description: 'Adversary uses query-efficient techniques to extract model with minimal API calls.',
    mitigations: Object.freeze(['AML.M0003', 'AML.M0005']),
  }),
  'AML.T0035': Object.freeze({
    id: 'AML.T0035',
    name: 'Transfer Learning Attack',
    tactic: 'ML Attack Staging',
    description: 'Adversary crafts attacks on surrogate models and transfers them to the target model.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0003']),
  }),

  // ── Execution ───────────────────────────────────────────────────────────
  'AML.T0040': Object.freeze({
    id: 'AML.T0040',
    name: 'Prompt Injection — Direct',
    tactic: 'Execution',
    description: 'Adversary directly injects malicious instructions into the user-facing prompt.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0006', 'AML.M0014']),
  }),
  'AML.T0041': Object.freeze({
    id: 'AML.T0041',
    name: 'Prompt Injection — Indirect',
    tactic: 'Execution',
    description: 'Adversary embeds malicious instructions in external data sources consumed by the LLM.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0006', 'AML.M0013']),
  }),
  'AML.T0042': Object.freeze({
    id: 'AML.T0042',
    name: 'Command Injection via LLM',
    tactic: 'Execution',
    description: 'Adversary tricks the LLM into executing system commands or shell operations.',
    mitigations: Object.freeze(['AML.M0006', 'AML.M0009', 'AML.M0014']),
  }),
  'AML.T0043': Object.freeze({
    id: 'AML.T0043',
    name: 'Code Execution via LLM Output',
    tactic: 'Execution',
    description: 'Adversary causes the LLM to produce output that is executed as code by downstream systems.',
    mitigations: Object.freeze(['AML.M0006', 'AML.M0009', 'AML.M0014']),
  }),
  'AML.T0044': Object.freeze({
    id: 'AML.T0044',
    name: 'Tool Manipulation',
    tactic: 'Execution',
    description: 'Adversary manipulates LLM tool-use to invoke unintended functions or parameters.',
    mitigations: Object.freeze(['AML.M0009', 'AML.M0006', 'AML.M0014']),
  }),
  'AML.T0045': Object.freeze({
    id: 'AML.T0045',
    name: 'MCP Protocol Exploitation',
    tactic: 'Execution',
    description: 'Adversary exploits Model Context Protocol to hijack tool routing or inject payloads.',
    mitigations: Object.freeze(['AML.M0009', 'AML.M0006', 'AML.M0013']),
  }),

  // ── Persistence ─────────────────────────────────────────────────────────
  'AML.T0050': Object.freeze({
    id: 'AML.T0050',
    name: 'Persistent Prompt Injection',
    tactic: 'Persistence',
    description: 'Adversary plants instructions that persist across conversation turns or sessions.',
    mitigations: Object.freeze(['AML.M0006', 'AML.M0008', 'AML.M0014']),
  }),
  'AML.T0051': Object.freeze({
    id: 'AML.T0051',
    name: 'LLM Prompt Injection',
    tactic: 'Persistence',
    description: 'Generic prompt injection technique covering all forms of instruction manipulation.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0006', 'AML.M0014']),
  }),
  'AML.T0052': Object.freeze({
    id: 'AML.T0052',
    name: 'Model Backdoor',
    tactic: 'Persistence',
    description: 'Adversary implants a backdoor trigger in the model during training or fine-tuning.',
    mitigations: Object.freeze(['AML.M0004', 'AML.M0007', 'AML.M0013']),
  }),
  'AML.T0053': Object.freeze({
    id: 'AML.T0053',
    name: 'Data Poisoning for Persistence',
    tactic: 'Persistence',
    description: 'Adversary poisons ongoing training data to maintain influence over model behavior.',
    mitigations: Object.freeze(['AML.M0007', 'AML.M0004']),
  }),
  'AML.T0054': Object.freeze({
    id: 'AML.T0054',
    name: 'System Prompt Extraction',
    tactic: 'Persistence',
    description: 'Adversary extracts the system prompt to understand constraints and craft bypasses.',
    mitigations: Object.freeze(['AML.M0006', 'AML.M0014', 'AML.M0002']),
  }),
  'AML.T0055': Object.freeze({
    id: 'AML.T0055',
    name: 'Memory Manipulation',
    tactic: 'Persistence',
    description: 'Adversary manipulates conversation memory or context window to persist malicious state.',
    mitigations: Object.freeze(['AML.M0008', 'AML.M0006']),
  }),

  // ── Privilege Escalation ────────────────────────────────────────────────
  'AML.T0060': Object.freeze({
    id: 'AML.T0060',
    name: 'Jailbreak',
    tactic: 'Privilege Escalation',
    description: 'Adversary bypasses safety guardrails to access restricted model capabilities.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0006', 'AML.M0014']),
  }),
  'AML.T0061': Object.freeze({
    id: 'AML.T0061',
    name: 'Role-Playing Attack',
    tactic: 'Privilege Escalation',
    description: 'Adversary uses role-play scenarios to trick the LLM into bypassing safety constraints.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0006']),
  }),
  'AML.T0062': Object.freeze({
    id: 'AML.T0062',
    name: 'DAN (Do Anything Now)',
    tactic: 'Privilege Escalation',
    description: 'Adversary uses DAN-style prompts to override model safety training.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0006', 'AML.M0014']),
  }),
  'AML.T0063': Object.freeze({
    id: 'AML.T0063',
    name: 'Multi-Turn Escalation',
    tactic: 'Privilege Escalation',
    description: 'Adversary gradually escalates requests across multiple conversation turns.',
    mitigations: Object.freeze(['AML.M0008', 'AML.M0002', 'AML.M0006']),
  }),
  'AML.T0064': Object.freeze({
    id: 'AML.T0064',
    name: 'Crescendo Attack',
    tactic: 'Privilege Escalation',
    description: 'Adversary slowly builds rapport and context to eventually extract restricted content.',
    mitigations: Object.freeze(['AML.M0008', 'AML.M0002']),
  }),
  'AML.T0065': Object.freeze({
    id: 'AML.T0065',
    name: 'Context Window Manipulation',
    tactic: 'Privilege Escalation',
    description: 'Adversary manipulates context window to push safety instructions out of attention.',
    mitigations: Object.freeze(['AML.M0008', 'AML.M0006']),
  }),

  // ── Defense Evasion ─────────────────────────────────────────────────────
  'AML.T0070': Object.freeze({
    id: 'AML.T0070',
    name: 'Encoding-Based Evasion',
    tactic: 'Defense Evasion',
    description: 'Adversary uses Base64, ROT13, hex, or other encodings to obfuscate malicious payloads.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0010']),
  }),
  'AML.T0071': Object.freeze({
    id: 'AML.T0071',
    name: 'Language-Based Evasion',
    tactic: 'Defense Evasion',
    description: 'Adversary translates prompts or uses pig latin, slang, or obscure languages to evade filters.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0010']),
  }),
  'AML.T0072': Object.freeze({
    id: 'AML.T0072',
    name: 'Unicode Obfuscation',
    tactic: 'Defense Evasion',
    description: 'Adversary uses Unicode homoglyphs, invisible chars, or bidirectional text to hide payloads.',
    mitigations: Object.freeze(['AML.M0010', 'AML.M0002']),
  }),
  'AML.T0073': Object.freeze({
    id: 'AML.T0073',
    name: 'Emoji Smuggling',
    tactic: 'Defense Evasion',
    description: 'Adversary encodes instructions within emoji sequences or variation selectors.',
    mitigations: Object.freeze(['AML.M0010', 'AML.M0002']),
  }),
  'AML.T0074': Object.freeze({
    id: 'AML.T0074',
    name: 'Cipher Obfuscation',
    tactic: 'Defense Evasion',
    description: 'Adversary uses simple ciphers (Caesar, substitution) to hide intent from detectors.',
    mitigations: Object.freeze(['AML.M0010', 'AML.M0002']),
  }),
  'AML.T0075': Object.freeze({
    id: 'AML.T0075',
    name: 'Token Smuggling',
    tactic: 'Defense Evasion',
    description: 'Adversary exploits tokenizer behavior to smuggle payloads across token boundaries.',
    mitigations: Object.freeze(['AML.M0010', 'AML.M0002']),
  }),
  'AML.T0076': Object.freeze({
    id: 'AML.T0076',
    name: 'Payload Fragmentation',
    tactic: 'Defense Evasion',
    description: 'Adversary splits malicious payload across multiple messages or input fields.',
    mitigations: Object.freeze(['AML.M0008', 'AML.M0002']),
  }),
  'AML.T0077': Object.freeze({
    id: 'AML.T0077',
    name: 'Steganographic Embedding',
    tactic: 'Defense Evasion',
    description: 'Adversary hides instructions in whitespace, zero-width chars, or non-visible formatting.',
    mitigations: Object.freeze(['AML.M0010', 'AML.M0002']),
  }),

  // ── Credential Access ───────────────────────────────────────────────────
  'AML.T0080': Object.freeze({
    id: 'AML.T0080',
    name: 'API Key Extraction',
    tactic: 'Credential Access',
    description: 'Adversary tricks the LLM into revealing API keys or tokens from its context.',
    mitigations: Object.freeze(['AML.M0006', 'AML.M0011', 'AML.M0014']),
  }),
  'AML.T0081': Object.freeze({
    id: 'AML.T0081',
    name: 'Credential Harvesting via LLM',
    tactic: 'Credential Access',
    description: 'Adversary uses the LLM to phish or extract credentials from users or connected systems.',
    mitigations: Object.freeze(['AML.M0006', 'AML.M0011']),
  }),
  'AML.T0082': Object.freeze({
    id: 'AML.T0082',
    name: 'Session Token Theft',
    tactic: 'Credential Access',
    description: 'Adversary extracts session tokens or auth cookies through LLM-mediated attacks.',
    mitigations: Object.freeze(['AML.M0011', 'AML.M0006']),
  }),

  // ── Discovery ───────────────────────────────────────────────────────────
  'AML.T0090': Object.freeze({
    id: 'AML.T0090',
    name: 'System Prompt Discovery',
    tactic: 'Discovery',
    description: 'Adversary probes the LLM to discover its system prompt, instructions, or constraints.',
    mitigations: Object.freeze(['AML.M0006', 'AML.M0014']),
  }),
  'AML.T0091': Object.freeze({
    id: 'AML.T0091',
    name: 'Model Architecture Probing',
    tactic: 'Discovery',
    description: 'Adversary systematically probes to determine model type, size, and capabilities.',
    mitigations: Object.freeze(['AML.M0003', 'AML.M0015']),
  }),
  'AML.T0092': Object.freeze({
    id: 'AML.T0092',
    name: 'Tool/Plugin Enumeration',
    tactic: 'Discovery',
    description: 'Adversary enumerates available tools, plugins, and integrations accessible to the LLM.',
    mitigations: Object.freeze(['AML.M0009', 'AML.M0006']),
  }),
  'AML.T0093': Object.freeze({
    id: 'AML.T0093',
    name: 'Permission Boundary Testing',
    tactic: 'Discovery',
    description: 'Adversary tests authorization boundaries to map what actions the LLM can perform.',
    mitigations: Object.freeze(['AML.M0009', 'AML.M0005']),
  }),

  // ── Lateral Movement ────────────────────────────────────────────────────
  'AML.T0100': Object.freeze({
    id: 'AML.T0100',
    name: 'Cross-Plugin Exploitation',
    tactic: 'Lateral Movement',
    description: 'Adversary exploits one plugin to compromise or access another connected plugin.',
    mitigations: Object.freeze(['AML.M0009', 'AML.M0013']),
  }),
  'AML.T0101': Object.freeze({
    id: 'AML.T0101',
    name: 'MCP Tool Chain Attack',
    tactic: 'Lateral Movement',
    description: 'Adversary chains MCP tool calls to traverse trust boundaries and access restricted resources.',
    mitigations: Object.freeze(['AML.M0009', 'AML.M0006']),
  }),
  'AML.T0102': Object.freeze({
    id: 'AML.T0102',
    name: 'Context Injection Across Sessions',
    tactic: 'Lateral Movement',
    description: 'Adversary injects context that persists and propagates to other user sessions.',
    mitigations: Object.freeze(['AML.M0008', 'AML.M0006']),
  }),

  // ── Collection ──────────────────────────────────────────────────────────
  'AML.T0110': Object.freeze({
    id: 'AML.T0110',
    name: 'Training Data Extraction',
    tactic: 'Collection',
    description: 'Adversary extracts memorized training data from the model through targeted queries.',
    mitigations: Object.freeze(['AML.M0003', 'AML.M0012']),
  }),
  'AML.T0111': Object.freeze({
    id: 'AML.T0111',
    name: 'Conversation History Exfiltration',
    tactic: 'Collection',
    description: 'Adversary accesses and extracts previous conversation history from the model context.',
    mitigations: Object.freeze(['AML.M0008', 'AML.M0006']),
  }),
  'AML.T0112': Object.freeze({
    id: 'AML.T0112',
    name: 'PII Extraction',
    tactic: 'Collection',
    description: 'Adversary tricks the LLM into revealing personally identifiable information.',
    mitigations: Object.freeze(['AML.M0006', 'AML.M0012', 'AML.M0011']),
  }),
  'AML.T0113': Object.freeze({
    id: 'AML.T0113',
    name: 'Model Weight Extraction',
    tactic: 'Collection',
    description: 'Adversary extracts model weights or parameters through repeated API interactions.',
    mitigations: Object.freeze(['AML.M0003', 'AML.M0005']),
  }),

  // ── Exfiltration ────────────────────────────────────────────────────────
  'AML.T0120': Object.freeze({
    id: 'AML.T0120',
    name: 'Data Exfiltration via LLM Output',
    tactic: 'Exfiltration',
    description: 'Adversary exfiltrates data by embedding it in the LLM response text.',
    mitigations: Object.freeze(['AML.M0006', 'AML.M0012']),
  }),
  'AML.T0121': Object.freeze({
    id: 'AML.T0121',
    name: 'DNS Covert Channel',
    tactic: 'Exfiltration',
    description: 'Adversary exfiltrates data via DNS queries triggered by LLM-generated content.',
    mitigations: Object.freeze(['AML.M0009', 'AML.M0012']),
  }),
  'AML.T0122': Object.freeze({
    id: 'AML.T0122',
    name: 'URL-Based Exfiltration',
    tactic: 'Exfiltration',
    description: 'Adversary embeds stolen data in URLs rendered by the LLM (image tags, links, etc.).',
    mitigations: Object.freeze(['AML.M0009', 'AML.M0012', 'AML.M0006']),
  }),
  'AML.T0123': Object.freeze({
    id: 'AML.T0123',
    name: 'Steganographic Exfiltration',
    tactic: 'Exfiltration',
    description: 'Adversary hides exfiltrated data in non-obvious channels within LLM output.',
    mitigations: Object.freeze(['AML.M0012', 'AML.M0010']),
  }),

  // ── Impact ──────────────────────────────────────────────────────────────
  'AML.T0130': Object.freeze({
    id: 'AML.T0130',
    name: 'Denial of ML Service',
    tactic: 'Impact',
    description: 'Adversary disrupts ML service availability through resource exhaustion or poisoning.',
    mitigations: Object.freeze(['AML.M0003', 'AML.M0005']),
  }),
  'AML.T0131': Object.freeze({
    id: 'AML.T0131',
    name: 'Model Degradation',
    tactic: 'Impact',
    description: 'Adversary gradually degrades model performance through sustained adversarial inputs.',
    mitigations: Object.freeze(['AML.M0004', 'AML.M0007']),
  }),
  'AML.T0132': Object.freeze({
    id: 'AML.T0132',
    name: 'Output Manipulation',
    tactic: 'Impact',
    description: 'Adversary causes the model to produce incorrect, biased, or harmful outputs.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0006']),
  }),
  'AML.T0133': Object.freeze({
    id: 'AML.T0133',
    name: 'Reputation Damage',
    tactic: 'Impact',
    description: 'Adversary causes the model to produce outputs that damage the deploying organization.',
    mitigations: Object.freeze(['AML.M0006', 'AML.M0002']),
  }),
  'AML.T0134': Object.freeze({
    id: 'AML.T0134',
    name: 'Resource Exhaustion',
    tactic: 'Impact',
    description: 'Adversary crafts inputs that consume disproportionate compute, memory, or API quota.',
    mitigations: Object.freeze(['AML.M0003', 'AML.M0005']),
  }),

  // ── LLM-Specific Attacks ────────────────────────────────────────────────
  'AML.T0140': Object.freeze({
    id: 'AML.T0140',
    name: 'Hallucination Exploitation',
    tactic: 'LLM-Specific Attacks',
    description: 'Adversary induces or exploits model hallucinations for social engineering or misinformation.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0006']),
  }),
  'AML.T0141': Object.freeze({
    id: 'AML.T0141',
    name: 'Instruction Hierarchy Bypass',
    tactic: 'LLM-Specific Attacks',
    description: 'Adversary subverts the instruction priority hierarchy (system > user > context).',
    mitigations: Object.freeze(['AML.M0006', 'AML.M0014']),
  }),
  'AML.T0142': Object.freeze({
    id: 'AML.T0142',
    name: 'Few-Shot Manipulation',
    tactic: 'LLM-Specific Attacks',
    description: 'Adversary uses carefully crafted few-shot examples to steer model behavior.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0006']),
  }),
  'AML.T0143': Object.freeze({
    id: 'AML.T0143',
    name: 'Chain-of-Thought Exploitation',
    tactic: 'LLM-Specific Attacks',
    description: 'Adversary exploits chain-of-thought reasoning to lead the model to harmful conclusions.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0006']),
  }),
  'AML.T0144': Object.freeze({
    id: 'AML.T0144',
    name: 'RLHF/Safety Training Bypass',
    tactic: 'LLM-Specific Attacks',
    description: 'Adversary finds systematic weaknesses in RLHF alignment to bypass safety training.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0014']),
  }),
  'AML.T0145': Object.freeze({
    id: 'AML.T0145',
    name: 'Virtual Context Attack',
    tactic: 'LLM-Specific Attacks',
    description: 'Adversary creates a virtual or simulated context to override real safety constraints.',
    mitigations: Object.freeze(['AML.M0006', 'AML.M0002']),
  }),
  'AML.T0146': Object.freeze({
    id: 'AML.T0146',
    name: 'Sandwich Attack',
    tactic: 'LLM-Specific Attacks',
    description: 'Adversary wraps malicious instructions between benign content to evade detection.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0010']),
  }),
  'AML.T0147': Object.freeze({
    id: 'AML.T0147',
    name: 'Many-Shot Jailbreak',
    tactic: 'LLM-Specific Attacks',
    description: 'Adversary provides many examples of the desired harmful behavior to overwhelm safety training.',
    mitigations: Object.freeze(['AML.M0008', 'AML.M0002']),
  }),
  'AML.T0148': Object.freeze({
    id: 'AML.T0148',
    name: 'ASCII Art Attack',
    tactic: 'LLM-Specific Attacks',
    description: 'Adversary uses ASCII art to represent harmful content that bypasses text-based filters.',
    mitigations: Object.freeze(['AML.M0010', 'AML.M0002']),
  }),
  'AML.T0149': Object.freeze({
    id: 'AML.T0149',
    name: 'Skeleton Key Attack',
    tactic: 'LLM-Specific Attacks',
    description: 'Adversary uses a master unlock prompt that disables all safety guardrails simultaneously.',
    mitigations: Object.freeze(['AML.M0002', 'AML.M0006', 'AML.M0014']),
  }),

  // ── Supply Chain ────────────────────────────────────────────────────────
  'AML.T0150': Object.freeze({
    id: 'AML.T0150',
    name: 'Malicious Model Upload',
    tactic: 'Supply Chain',
    description: 'Adversary uploads trojaned models to public registries under legitimate-sounding names.',
    mitigations: Object.freeze(['AML.M0013', 'AML.M0004']),
  }),
  'AML.T0151': Object.freeze({
    id: 'AML.T0151',
    name: 'Backdoored Fine-Tune',
    tactic: 'Supply Chain',
    description: 'Adversary distributes fine-tuned models containing hidden backdoor behaviors.',
    mitigations: Object.freeze(['AML.M0004', 'AML.M0013', 'AML.M0007']),
  }),
  'AML.T0152': Object.freeze({
    id: 'AML.T0152',
    name: 'Poisoned Adapter/LoRA',
    tactic: 'Supply Chain',
    description: 'Adversary distributes poisoned LoRA adapters that introduce malicious behaviors.',
    mitigations: Object.freeze(['AML.M0004', 'AML.M0013']),
  }),
  'AML.T0153': Object.freeze({
    id: 'AML.T0153',
    name: 'Compromised Embedding Model',
    tactic: 'Supply Chain',
    description: 'Adversary compromises an embedding model to bias retrieval in RAG pipelines.',
    mitigations: Object.freeze(['AML.M0013', 'AML.M0004', 'AML.M0007']),
  }),
})

// ---------------------------------------------------------------------------
// Scanner-to-ATLAS Mapping
// ---------------------------------------------------------------------------

/**
 * Maps ShieldX scanner IDs to the ATLAS technique IDs they are designed to detect.
 * Used to determine which techniques a scan result covers.
 */
export const SCANNER_TO_ATLAS_MAP: Readonly<Record<string, readonly string[]>> = Object.freeze({
  'rule-engine':                Object.freeze(['AML.T0040', 'AML.T0051', 'AML.T0060', 'AML.T0061', 'AML.T0062', 'AML.T0141']),
  'cipher-decoder':             Object.freeze(['AML.T0070', 'AML.T0074', 'AML.T0071']),
  'semantic-contrastive-scanner': Object.freeze(['AML.T0031', 'AML.T0051', 'AML.T0060']),
  'entropy-scanner':            Object.freeze(['AML.T0121', 'AML.T0075']),
  'unicode-scanner':            Object.freeze(['AML.T0072', 'AML.T0077']),
  'emoji-smuggling':            Object.freeze(['AML.T0073']),
  'upside-down-text':           Object.freeze(['AML.T0071']),
  'conversation-tracker':       Object.freeze(['AML.T0063', 'AML.T0064', 'AML.T0055']),
  'intent-monitor':             Object.freeze(['AML.T0090', 'AML.T0093']),
  'context-integrity':          Object.freeze(['AML.T0065', 'AML.T0102']),
  'auth-context-guard':         Object.freeze(['AML.T0060', 'AML.T0080', 'AML.T0082']),
  'decomposition-detector':     Object.freeze(['AML.T0063', 'AML.T0064', 'AML.T0076']),
  'indirect-injection':         Object.freeze(['AML.T0041', 'AML.T0044', 'AML.T0100']),
  'resource-exhaustion':        Object.freeze(['AML.T0130', 'AML.T0134']),
  'output-sanitizer':           Object.freeze(['AML.T0054', 'AML.T0120']),
  'output-payload-guard':       Object.freeze(['AML.T0042', 'AML.T0043', 'AML.T0122']),
  'tool-call-safety-guard':     Object.freeze(['AML.T0042', 'AML.T0044', 'AML.T0045']),
  'melon-guard':                Object.freeze(['AML.T0041', 'AML.T0044', 'AML.T0045']),
  'credential-redactor':        Object.freeze(['AML.T0080', 'AML.T0112']),
  'canary-manager':             Object.freeze(['AML.T0054', 'AML.T0111']),
  'model-integrity-guard':      Object.freeze(['AML.T0150', 'AML.T0151', 'AML.T0152', 'AML.T0153']),
  'kill-chain-mapper':          Object.freeze(['AML.T0051']),
  'rate-limiter':               Object.freeze(['AML.T0130', 'AML.T0134']),
})

// ---------------------------------------------------------------------------
// ATLASMapper
// ---------------------------------------------------------------------------

/**
 * Maps ShieldX scan results to MITRE ATLAS techniques.
 *
 * Provides per-result technique mapping, batch processing,
 * and full coverage analysis across all 84+ ATLAS techniques.
 */
export class ATLASMapper {
  private readonly techniqueIndex: ReadonlyMap<string, ATLASTechnique>
  private readonly tacticIndex: ReadonlyMap<string, readonly ATLASTechnique[]>

  constructor() {
    this.techniqueIndex = this.buildTechniqueIndex()
    this.tacticIndex = this.buildTacticIndex()
  }

  /**
   * Map a single ScanResult to its matching ATLAS techniques.
   */
  mapResult(result: ScanResult): ATLASMapping {
    const techniqueIds = SCANNER_TO_ATLAS_MAP[result.scannerId] ?? []
    const techniques = techniqueIds
      .map((id) => this.techniqueIndex.get(id))
      .filter((t): t is ATLASTechnique => t !== undefined)

    return Object.freeze({
      scannerId: result.scannerId,
      techniques: Object.freeze(techniques),
      primaryTechnique: techniques[0] ?? null,
    })
  }

  /**
   * Map an array of ScanResults to their matching ATLAS techniques.
   */
  mapResults(results: readonly ScanResult[]): readonly ATLASMapping[] {
    return Object.freeze(results.map((r) => this.mapResult(r)))
  }

  /**
   * Compute coverage statistics across all ATLAS techniques.
   * Determines which techniques are covered by at least one ShieldX scanner.
   */
  getCoverage(): ATLASCoverage {
    const allTechniqueIds = Object.keys(ATLAS_TECHNIQUES)
    const coveredIds = new Set<string>()

    for (const ids of Object.values(SCANNER_TO_ATLAS_MAP)) {
      for (const id of ids) {
        coveredIds.add(id)
      }
    }

    const uncoveredTechniques = allTechniqueIds
      .filter((id) => !coveredIds.has(id))
      .map((id) => ATLAS_TECHNIQUES[id])
      .filter((t): t is ATLASTechnique => t !== undefined)

    const coverageByTactic = this.computeTacticCoverage(allTechniqueIds, coveredIds)

    const totalTechniques = allTechniqueIds.length
    const coveredCount = coveredIds.size
    const coveragePercent = totalTechniques > 0
      ? Math.round((coveredCount / totalTechniques) * 10000) / 100
      : 0

    return Object.freeze({
      totalTechniques,
      coveredTechniques: coveredCount,
      coveragePercent,
      uncoveredTechniques: Object.freeze(uncoveredTechniques),
      coverageByTactic: coverageByTactic,
    })
  }

  /**
   * Look up a single ATLAS technique by its ID.
   */
  getTechniqueById(id: string): ATLASTechnique | undefined {
    return this.techniqueIndex.get(id)
  }

  /**
   * Get all ATLAS techniques belonging to a specific tactic.
   */
  getTechniquesByTactic(tactic: string): readonly ATLASTechnique[] {
    return this.tacticIndex.get(tactic) ?? []
  }

  // ── Private helpers ─────────────────────────────────────────────────────

  private buildTechniqueIndex(): ReadonlyMap<string, ATLASTechnique> {
    const map = new Map<string, ATLASTechnique>()
    for (const technique of Object.values(ATLAS_TECHNIQUES)) {
      map.set(technique.id, technique)
    }
    return map
  }

  private buildTacticIndex(): ReadonlyMap<string, readonly ATLASTechnique[]> {
    const map = new Map<string, ATLASTechnique[]>()
    for (const technique of Object.values(ATLAS_TECHNIQUES)) {
      const existing = map.get(technique.tactic) ?? []
      map.set(technique.tactic, [...existing, technique])
    }
    // Freeze inner arrays
    const frozen = new Map<string, readonly ATLASTechnique[]>()
    for (const [tactic, techniques] of map) {
      frozen.set(tactic, Object.freeze(techniques))
    }
    return frozen
  }

  private computeTacticCoverage(
    allIds: readonly string[],
    coveredIds: ReadonlySet<string>
  ): ReadonlyMap<string, { total: number; covered: number }> {
    const tacticTotals = new Map<string, { total: number; covered: number }>()

    for (const id of allIds) {
      const technique = ATLAS_TECHNIQUES[id]
      if (!technique) continue

      const entry = tacticTotals.get(technique.tactic) ?? { total: 0, covered: 0 }
      const updatedTotal = entry.total + 1
      const updatedCovered = entry.covered + (coveredIds.has(id) ? 1 : 0)
      tacticTotals.set(technique.tactic, { total: updatedTotal, covered: updatedCovered })
    }

    return tacticTotals
  }
}
