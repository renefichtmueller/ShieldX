/**
 * MITRE ATLAS technique mapping.
 * Maps ShieldX rule IDs to MITRE ATLAS technique IDs
 * for compliance reporting and gap analysis.
 */

import type { ATLASMapping } from '../types/compliance.js'

/**
 * Hardcoded mapping of ShieldX rule IDs to ATLAS techniques.
 * Based on MITRE ATLAS v4.0 (Adversarial Threat Landscape for AI Systems).
 */
const ATLAS_MAPPINGS: Readonly<Record<string, ATLASMapping>> = {
  // Prompt Injection / Initial Access
  'rule:prompt-injection': {
    techniqueId: 'AML.T0051',
    tacticId: 'AML.TA0004',
    techniqueName: 'LLM Prompt Injection',
    tacticName: 'Initial Access',
    description: 'Adversary crafts input to override LLM instructions and manipulate model behavior',
    relatedKillChainPhase: 'initial_access',
    mitigationIds: ['AML.M0015', 'AML.M0016'],
    caseStudyIds: ['AML.CS0016'],
  },
  'rule:prompt-injection-indirect': {
    techniqueId: 'AML.T0051.001',
    tacticId: 'AML.TA0004',
    techniqueName: 'LLM Prompt Injection: Indirect',
    tacticName: 'Initial Access',
    description: 'Adversary places malicious instructions in external data sources consumed by the LLM',
    relatedKillChainPhase: 'initial_access',
    mitigationIds: ['AML.M0015', 'AML.M0016', 'AML.M0018'],
    caseStudyIds: ['AML.CS0016'],
  },
  // Jailbreak / Privilege Escalation
  'rule:jailbreak': {
    techniqueId: 'AML.T0054',
    tacticId: 'AML.TA0005',
    techniqueName: 'LLM Jailbreak',
    tacticName: 'Defense Evasion',
    description: 'Adversary bypasses safety guardrails to make the model generate harmful content',
    relatedKillChainPhase: 'privilege_escalation',
    mitigationIds: ['AML.M0015', 'AML.M0019'],
    caseStudyIds: ['AML.CS0017'],
  },
  // Model Extraction / Reconnaissance
  'rule:model-extraction': {
    techniqueId: 'AML.T0024',
    tacticId: 'AML.TA0002',
    techniqueName: 'Exfiltration via ML Inference API',
    tacticName: 'Exfiltration',
    description: 'Adversary extracts model parameters or training data via repeated API queries',
    relatedKillChainPhase: 'reconnaissance',
    mitigationIds: ['AML.M0008', 'AML.M0012'],
    caseStudyIds: ['AML.CS0005'],
  },
  // System Prompt Extraction
  'rule:system-prompt-extraction': {
    techniqueId: 'AML.T0051.002',
    tacticId: 'AML.TA0007',
    techniqueName: 'LLM Prompt Injection: System Prompt Extraction',
    tacticName: 'Collection',
    description: 'Adversary attempts to extract the system prompt or internal instructions',
    relatedKillChainPhase: 'reconnaissance',
    mitigationIds: ['AML.M0015', 'AML.M0016'],
    caseStudyIds: [],
  },
  // Data Poisoning
  'rule:data-poisoning': {
    techniqueId: 'AML.T0020',
    tacticId: 'AML.TA0003',
    techniqueName: 'Poison Training Data',
    tacticName: 'Persistence',
    description: 'Adversary manipulates training or fine-tuning data to insert backdoors',
    relatedKillChainPhase: 'persistence',
    mitigationIds: ['AML.M0007', 'AML.M0014'],
    caseStudyIds: ['AML.CS0014'],
  },
  // Supply Chain
  'rule:supply-chain': {
    techniqueId: 'AML.T0010',
    tacticId: 'AML.TA0001',
    techniqueName: 'ML Supply Chain Compromise',
    tacticName: 'Initial Access',
    description: 'Adversary compromises ML supply chain components (models, libraries, data)',
    relatedKillChainPhase: 'initial_access',
    mitigationIds: ['AML.M0013', 'AML.M0014'],
    caseStudyIds: ['AML.CS0013'],
  },
  // Encoding / Evasion
  'rule:encoding-evasion': {
    techniqueId: 'AML.T0015',
    tacticId: 'AML.TA0005',
    techniqueName: 'Evade ML Model',
    tacticName: 'Defense Evasion',
    description: 'Adversary uses encoding or obfuscation to evade detection models',
    relatedKillChainPhase: 'initial_access',
    mitigationIds: ['AML.M0004', 'AML.M0015'],
    caseStudyIds: ['AML.CS0003'],
  },
  // MCP Tool Abuse
  'rule:tool-abuse': {
    techniqueId: 'AML.T0040',
    tacticId: 'AML.TA0006',
    techniqueName: 'ML Model Inference API Access',
    tacticName: 'Execution',
    description: 'Adversary abuses tool-calling capabilities to execute unauthorized actions',
    relatedKillChainPhase: 'command_and_control',
    mitigationIds: ['AML.M0008', 'AML.M0012'],
    caseStudyIds: [],
  },
  // Exfiltration
  'rule:data-exfiltration': {
    techniqueId: 'AML.T0025',
    tacticId: 'AML.TA0002',
    techniqueName: 'Exfiltration via Cyber Means',
    tacticName: 'Exfiltration',
    description: 'Adversary exfiltrates sensitive data through LLM-controlled outputs or tools',
    relatedKillChainPhase: 'actions_on_objective',
    mitigationIds: ['AML.M0008', 'AML.M0012'],
    caseStudyIds: [],
  },
  // DNS Covert Channel Exfiltration (ChatGPT CVE Feb 2026, CVE-2025-55284, AWS AgentCore)
  'rule:dns-exfiltration': {
    techniqueId: 'AML.T0025',
    tacticId: 'AML.TA0002',
    techniqueName: 'Exfiltration via Cyber Means — DNS Covert Channel',
    tacticName: 'Exfiltration',
    description: 'DNS subdomain encoding for covert exfiltration — bypasses TCP/UDP firewall rules by embedding Base32/Base64 encoded data in DNS query labels routed to attacker-controlled authoritative nameserver. Exploits LLM code execution sandbox assumption that DNS is a system-only service.',
    relatedKillChainPhase: 'actions_on_objective',
    mitigationIds: ['AML.M0008', 'AML.M0012', 'AML.M0015'],
    caseStudyIds: [],
  },
  // Allowlist Bypass via Diagnostic Tools (CVE-2025-55284)
  'rule:tool-allowlist-bypass': {
    techniqueId: 'AML.T0051.002',
    tacticId: 'AML.TA0001',
    techniqueName: 'Indirect Prompt Injection — Tool Allowlist Bypass',
    tacticName: 'Initial Access',
    description: 'Injected instructions exploit whitelisted diagnostic tools (ping, nslookup, dig, host) that bypass approval dialogs. Data encoded in DNS hostname arguments to these tools creates exfiltration channel invisible to guardrails. Fixed in Claude Code v1.0.4 (CVE-2025-55284, CVSS 7.1).',
    relatedKillChainPhase: 'command_and_control',
    mitigationIds: ['AML.M0008', 'AML.M0012'],
    caseStudyIds: [],
  },
  // Markdown Image Exfiltration (EchoLeak / CVE-2025-32711, CVSS 9.3)
  'rule:markdown-render-exfiltration': {
    techniqueId: 'AML.T0051.002',
    tacticId: 'AML.TA0002',
    techniqueName: 'Indirect Prompt Injection — Markdown Auto-Fetch Exfiltration',
    tacticName: 'Exfiltration',
    description: 'Reference-style Markdown image tags trigger automatic browser resource fetches. Data embedded in URL parameters (base64) is transmitted to attacker server via rendering pipeline — exploits browser CSP allowlist entries. EchoLeak / CVE-2025-32711 (CVSS 9.3 Critical).',
    relatedKillChainPhase: 'actions_on_objective',
    mitigationIds: ['AML.M0008', 'AML.M0016'],
    caseStudyIds: [],
  },
  // Unicode Steganography / ASCII Smuggling (FireTail Sep 2025, AWS Security Blog)
  'rule:unicode-steganography': {
    techniqueId: 'AML.T0043',
    tacticId: 'AML.TA0005',
    techniqueName: 'Craft Adversarial Data — Unicode Steganography',
    tacticName: 'Defense Evasion',
    description: 'Unicode Tags Block (U+E0000-U+E007F), Variant Selectors, and Zero-Width characters encode hidden instructions invisible in most UIs. Bypasses keyword filters entirely. References: FireTail Sep 2025, AWS Security Blog, Embrace The Red. OWASP LLM01:2025.',
    relatedKillChainPhase: 'initial_access',
    mitigationIds: ['AML.M0015', 'AML.M0004'],
    caseStudyIds: [],
  },
  // CamoLeak — Image-Ordering Exfiltration via CDN (CVE-2025-53773, GitHub Copilot)
  'rule:camoleak-exfiltration': {
    techniqueId: 'AML.T0025',
    tacticId: 'AML.TA0002',
    techniqueName: 'Exfiltration via Cyber Means — Image-Ordering Channel',
    tacticName: 'Exfiltration',
    description: 'Data encoded in the SEQUENCE of ~100 1×1 pixel image requests, not URL parameters. Uses whitelisted CDN/image proxy (GitHub Camo) to bypass CSP. Exfiltrates source code, secrets, credentials. CVE-2025-53773 (GitHub Copilot), CVSS 7.8. Detected via sequential image ID patterns.',
    relatedKillChainPhase: 'actions_on_objective',
    mitigationIds: ['AML.M0008', 'AML.M0016'],
    caseStudyIds: [],
  },
  // Agent Tool Invocation Exfiltration (AML.T0062 — added ATLAS v5.1 Nov 2025)
  'rule:agent-tool-exfiltration': {
    techniqueId: 'AML.T0062',
    tacticId: 'AML.TA0015',
    techniqueName: 'Exfiltration via AI Agent Tool Invocation',
    tacticName: 'Command and Control',
    description: 'Compromised LLM agent invokes legitimate tools (HTTP requests, email send, GitHub commit, webhook calls) with sensitive data encoded in tool parameters. The "Lethal Trifecta": untrusted input + sensitive data access + outbound communication capability. Log-To-Leak framework (OpenReview 2025). AML.TA0015 (C2 tactic added Nov 2025).',
    relatedKillChainPhase: 'actions_on_objective',
    mitigationIds: ['AML.M0008', 'AML.M0012', 'AML.M0015'],
    caseStudyIds: [],
  },
  // Memory Poisoning / Persistent Context Injection (MemoryGraft, MINJA)
  'rule:memory-poisoning': {
    techniqueId: 'AML.T0020',
    tacticId: 'AML.TA0003',
    techniqueName: 'Poison Training Data — LLM Memory Poisoning',
    tacticName: 'Persistence',
    description: 'Injects malicious instructions into LLM long-term memory (ChatGPT memories, Gemini saved info, vector DB). Temporally decoupled — poison planted today executes in future sessions. MINJA achieves >70% success rate via query-only interaction. MemoryGraft exploits semantic imitation heuristic (arXiv 2512.16962). Unit42 "When AI Remembers Too Much" (2025).',
    relatedKillChainPhase: 'persistence',
    mitigationIds: ['AML.M0007', 'AML.M0014', 'AML.M0015'],
    caseStudyIds: [],
  },
  // Multi-Agent Trust Exploitation / Agent-in-the-Middle
  'rule:multi-agent-trust-exploitation': {
    techniqueId: 'AML.T0051',
    tacticId: 'AML.TA0015',
    techniqueName: 'LLM Prompt Injection — Multi-Agent Trust Exploitation',
    tacticName: 'Command and Control',
    description: '82.4% of LLMs vulnerable to inter-agent attacks vs 41.2% for direct injection. Compromised agents pass payloads to peer agents with implicit elevated trust. Morris II worm self-replicates via email agent pipeline. Agent-in-the-Middle intercepts inter-agent messages causing DoS/propagation in >90% of tested topologies (arXiv 2509.14285).',
    relatedKillChainPhase: 'lateral_movement',
    mitigationIds: ['AML.M0015', 'AML.M0016', 'AML.M0018'],
    caseStudyIds: [],
  },
  // LLM Data Harvesting via Information Repositories (AML.T0036)
  'rule:data-repository-harvest': {
    techniqueId: 'AML.T0036',
    tacticId: 'AML.TA0002',
    techniqueName: 'Data from Information Repositories',
    tacticName: 'Collection',
    description: 'Adversary instructs LLM to harvest data from accessible information repositories (RAG stores, uploaded files, SharePoint, OneDrive) then exfiltrate via covert channel. Used in ChatGPT medical file PoC and EchoLeak SharePoint exfiltration.',
    relatedKillChainPhase: 'reconnaissance',
    mitigationIds: ['AML.M0008', 'AML.M0012'],
    caseStudyIds: [],
  },
  // Adversarial Example
  'rule:adversarial-example': {
    techniqueId: 'AML.T0043',
    tacticId: 'AML.TA0005',
    techniqueName: 'Craft Adversarial Data',
    tacticName: 'Defense Evasion',
    description: 'Adversary crafts inputs designed to cause misclassification or unsafe behavior',
    relatedKillChainPhase: 'initial_access',
    mitigationIds: ['AML.M0004', 'AML.M0015'],
    caseStudyIds: ['AML.CS0002'],
  },
} as const

/** Total known ATLAS techniques relevant to LLM security (ATLAS v5.4.0 Feb 2026) */
const TOTAL_ATLAS_TECHNIQUES = 29

/**
 * ATLASMapper — maps ShieldX rules to MITRE ATLAS techniques.
 *
 * Provides compliance coverage analysis against the MITRE ATLAS
 * framework for adversarial threats to AI systems.
 */
export class ATLASMapper {
  private readonly mappings: Readonly<Record<string, ATLASMapping>>

  constructor() {
    this.mappings = ATLAS_MAPPINGS
  }

  /**
   * Map a ShieldX rule ID to its ATLAS technique.
   * @param ruleId - ShieldX rule identifier
   * @returns ATLAS mapping if exists, undefined otherwise
   */
  mapRule(ruleId: string): ATLASMapping | undefined {
    return this.mappings[ruleId]
  }

  /**
   * Get all rule IDs that have ATLAS mappings.
   */
  getMappedRules(): readonly string[] {
    return Object.freeze(Object.keys(this.mappings))
  }

  /**
   * Calculate coverage of ATLAS techniques.
   * @returns Coverage statistics with gaps
   */
  getCoverage(): { covered: number; total: number; gaps: readonly string[] } {
    const coveredTechniques = new Set<string>()
    for (const mapping of Object.values(this.mappings)) {
      coveredTechniques.add(mapping.techniqueId)
    }

    // ATLAS v5.4.0 (Feb 2026): 16 tactics, 84 techniques, 56 sub-techniques
    // New Nov 2025: AML.TA0015 (C2 tactic), AML.T0062 (Agent Tool Invocation)
    const allKnownTechniques = [
      'AML.T0010', 'AML.T0015', 'AML.T0016', 'AML.T0018',
      'AML.T0020', 'AML.T0024', 'AML.T0025', 'AML.T0036',
      'AML.T0040', 'AML.T0042', 'AML.T0043', 'AML.T0044',
      'AML.T0047', 'AML.T0048', 'AML.T0049', 'AML.T0050',
      'AML.T0051', 'AML.T0051.001', 'AML.T0051.002', 'AML.T0052',
      'AML.T0053', 'AML.T0054', 'AML.T0062', 'AML.TA0015',
    ]

    const gaps = allKnownTechniques.filter((t) => !coveredTechniques.has(t))

    return Object.freeze({
      covered: coveredTechniques.size,
      total: TOTAL_ATLAS_TECHNIQUES,
      gaps: Object.freeze(gaps),
    })
  }

  /**
   * Get all mappings as an array.
   */
  getAllMappings(): readonly ATLASMapping[] {
    return Object.freeze(Object.values(this.mappings))
  }
}
