/**
 * OWASP LLM Top 10 2025 mapping.
 * Maps ShieldX rule IDs to OWASP LLM Top 10 risk categories
 * for compliance reporting and gap analysis.
 */

import type { OWASPMapping } from '../types/compliance.js'

/**
 * OWASP LLM Top 10 2025 full mapping.
 * Covers all 10 risk categories (LLM01-LLM10).
 */
const OWASP_MAPPINGS: Readonly<Record<string, OWASPMapping>> = {
  'rule:prompt-injection': {
    riskId: 'LLM01',
    riskName: 'Prompt Injection',
    description: 'Manipulating LLMs via crafted inputs that override system instructions, leading to unauthorized actions or data exposure',
    relatedKillChainPhases: ['initial_access', 'privilege_escalation'],
    preventionMeasures: [
      'Input validation and sanitization',
      'Privilege control for LLM access',
      'Human-in-the-loop for critical operations',
      'Segregate external content from user prompts',
    ],
    shieldxCoverage: [
      'RuleEngine', 'SentinelClassifier', 'ConstitutionalChecker',
      'EmbeddingScanner', 'CanaryManager', 'IndirectInjectionDetector',
      'OutputValidator', 'RAGShield', 'IntentGuardValidator',
    ],
  },
  'rule:sensitive-disclosure': {
    riskId: 'LLM02',
    riskName: 'Sensitive Information Disclosure',
    description: 'LLMs may inadvertently reveal sensitive data in outputs, exposing PII, proprietary info, or system details',
    relatedKillChainPhases: ['reconnaissance', 'actions_on_objective'],
    preventionMeasures: [
      'Data sanitization and scrubbing',
      'Input/output filtering',
      'Restrict training data access',
      'User awareness of data risks',
    ],
    shieldxCoverage: [
      'LeakageDetector', 'CanaryManager', 'OutputValidator',
      'ContextIntegrity', 'MemoryIntegrityGuard',
    ],
  },
  'rule:supply-chain': {
    riskId: 'LLM03',
    riskName: 'Supply Chain Vulnerabilities',
    description: 'LLM supply chains risk tampering with training data, models, or deployment platforms, introducing vulnerabilities',
    relatedKillChainPhases: ['initial_access', 'persistence'],
    preventionMeasures: [
      'Vet data sources and suppliers',
      'Use signed model artifacts',
      'Monitor for anomalous behavior',
      'Implement SBOM for ML components',
    ],
    shieldxCoverage: [
      'SupplyChainVerifier', 'ModelProvenanceChecker',
    ],
  },
  'rule:data-model-poisoning': {
    riskId: 'LLM04',
    riskName: 'Data and Model Poisoning',
    description: 'Tampering with pre-training, fine-tuning, or embedding data to introduce vulnerabilities, backdoors, or biases',
    relatedKillChainPhases: ['persistence', 'actions_on_objective'],
    preventionMeasures: [
      'Verify supply chain of training data',
      'Sandboxing and data validation',
      'Monitor for behavioral shifts',
      'Adversarial robustness testing',
    ],
    shieldxCoverage: [
      'EmbeddingStore', 'DriftDetector', 'SupplyChainVerifier',
    ],
  },
  'rule:improper-output': {
    riskId: 'LLM05',
    riskName: 'Improper Output Handling',
    description: 'LLM outputs used without validation can expose systems to XSS, SSRF, privilege escalation, and remote code execution',
    relatedKillChainPhases: ['actions_on_objective', 'lateral_movement'],
    preventionMeasures: [
      'Treat model output as untrusted',
      'Input validation on LLM output',
      'Follow OWASP ASVS guidelines',
      'Encode outputs for downstream context',
    ],
    shieldxCoverage: [
      'OutputValidator', 'ScopeValidator', 'RoleIntegrityChecker',
    ],
  },
  'rule:excessive-agency': {
    riskId: 'LLM06',
    riskName: 'Excessive Agency',
    description: 'LLM-based systems may undertake actions with unintended consequences due to excessive functionality or permissions',
    relatedKillChainPhases: ['command_and_control', 'lateral_movement'],
    preventionMeasures: [
      'Limit plugin/tool functionality',
      'Restrict LLM permissions',
      'Human-in-the-loop for high-impact actions',
      'Implement authorization and rate limiting',
    ],
    shieldxCoverage: [
      'ToolCallValidator', 'MCPGuard', 'ResourceGovernor',
      'ToolChainGuard', 'IntentMonitor',
    ],
  },
  'rule:system-prompt-leakage': {
    riskId: 'LLM07',
    riskName: 'System Prompt Leakage',
    description: 'System prompts or instructions may be exposed through crafted queries revealing proprietary logic or security controls',
    relatedKillChainPhases: ['reconnaissance'],
    preventionMeasures: [
      'Separate system prompts from user input',
      'Enforce output controls',
      'Apply trust boundaries',
      'Use canary tokens for leak detection',
    ],
    shieldxCoverage: [
      'LeakageDetector', 'CanaryManager', 'OutputValidator',
    ],
  },
  'rule:vector-embedding-weakness': {
    riskId: 'LLM08',
    riskName: 'Vector and Embedding Weaknesses',
    description: 'Vulnerabilities in how vectors and embeddings are generated or stored, leading to unauthorized access or manipulation',
    relatedKillChainPhases: ['initial_access', 'persistence'],
    preventionMeasures: [
      'Implement access controls on vector DBs',
      'Input validation before embedding',
      'Monitor for anomalous vectors',
      'Data integrity checks',
    ],
    shieldxCoverage: [
      'EmbeddingStore', 'EmbeddingScanner', 'RAGShield',
    ],
  },
  'rule:misinformation': {
    riskId: 'LLM09',
    riskName: 'Misinformation',
    description: 'LLMs generating false or misleading information that appears authoritative, leading to security issues or reputational damage',
    relatedKillChainPhases: ['actions_on_objective'],
    preventionMeasures: [
      'RAG with trusted sources',
      'Cross-verification mechanisms',
      'Output disclaimers',
      'User education on AI limitations',
    ],
    shieldxCoverage: [
      'RAGShield', 'ScopeValidator', 'ContextIntegrity',
    ],
  },
  'rule:unbounded-consumption': {
    riskId: 'LLM10',
    riskName: 'Unbounded Consumption',
    description: 'LLMs are susceptible to denial-of-service attacks through resource-heavy requests, variable-length inputs, or recursive processing',
    relatedKillChainPhases: ['command_and_control'],
    preventionMeasures: [
      'Input size limits and validation',
      'Rate limiting per user/API',
      'Resource monitoring and caps',
      'Query complexity analysis',
    ],
    shieldxCoverage: [
      'ResourceGovernor', 'EntropyScanner', 'TokenizerScanner',
    ],
  },
} as const

/** Total OWASP LLM risks */
const TOTAL_OWASP_RISKS = 10

/**
 * OWASPMapper — maps ShieldX rules to OWASP LLM Top 10 2025.
 *
 * Provides compliance coverage analysis against the OWASP LLM
 * Top 10 risk categories for large language model applications.
 */
export class OWASPMapper {
  private readonly mappings: Readonly<Record<string, OWASPMapping>>

  constructor() {
    this.mappings = OWASP_MAPPINGS
  }

  /**
   * Map a ShieldX rule ID to its OWASP LLM risk.
   * @param ruleId - ShieldX rule identifier
   * @returns OWASP mapping if exists, undefined otherwise
   */
  mapRule(ruleId: string): OWASPMapping | undefined {
    return this.mappings[ruleId]
  }

  /**
   * Get all rule IDs that have OWASP mappings.
   */
  getMappedRules(): readonly string[] {
    return Object.freeze(Object.keys(this.mappings))
  }

  /**
   * Calculate coverage of OWASP LLM Top 10.
   * @returns Coverage statistics with gaps
   */
  getCoverage(): { covered: number; total: number; gaps: readonly string[] } {
    const coveredRisks = new Set<string>()
    for (const mapping of Object.values(this.mappings)) {
      coveredRisks.add(mapping.riskId)
    }

    const allRisks = [
      'LLM01', 'LLM02', 'LLM03', 'LLM04', 'LLM05',
      'LLM06', 'LLM07', 'LLM08', 'LLM09', 'LLM10',
    ]

    const gaps = allRisks.filter((r) => !coveredRisks.has(r))

    return Object.freeze({
      covered: coveredRisks.size,
      total: TOTAL_OWASP_RISKS,
      gaps: Object.freeze(gaps),
    })
  }

  /**
   * Get all mappings as an array.
   */
  getAllMappings(): readonly OWASPMapping[] {
    return Object.freeze(Object.values(this.mappings))
  }
}
