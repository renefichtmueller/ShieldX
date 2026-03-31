/**
 * Default configuration for ShieldX.
 * All layers independently toggleable. Local-first defaults.
 */

import type { ShieldXConfig } from '../types/detection.js'

/** Deep merge utility for config objects */
export function mergeConfig(
  base: ShieldXConfig,
  overrides: DeepPartial<ShieldXConfig>,
): ShieldXConfig {
  return deepMerge(base, overrides) as ShieldXConfig
}

type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P]
}

function deepMerge(target: unknown, source: unknown): unknown {
  if (source === undefined || source === null) return target
  if (typeof target !== 'object' || target === null) return source
  if (typeof source !== 'object') return source

  const result = { ...target as Record<string, unknown> }
  for (const key of Object.keys(source as Record<string, unknown>)) {
    const sourceVal = (source as Record<string, unknown>)[key]
    const targetVal = result[key]
    result[key] = deepMerge(targetVal, sourceVal)
  }
  return result
}

/** Default configuration — local-first, all core layers enabled */
export const defaultConfig: ShieldXConfig = {
  thresholds: {
    low: 0.3,
    medium: 0.5,
    high: 0.7,
    critical: 0.9,
  },

  scanners: {
    rules: true,
    sentinel: false,        // Requires model download
    constitutional: false,   // Requires model download
    embedding: true,         // Requires Ollama
    embeddingAnomaly: true,
    entropy: true,
    yara: false,             // Requires YARA binary
    attention: false,        // Requires Ollama with attention output
    canary: true,
    indirect: true,
    selfConsciousness: false, // Expensive LLM call, opt-in
    crossModel: false,
    behavioral: true,
    unicode: true,           // Always on — zero cost, high impact
    tokenizer: true,
    compressedPayload: true,
  },

  healing: {
    enabled: true,
    autoSanitize: true,
    sessionReset: true,
    phaseStrategies: {
      initial_access: 'sanitize',
      privilege_escalation: 'block',
      reconnaissance: 'block',
      persistence: 'reset',
      command_and_control: 'incident',
      lateral_movement: 'incident',
      actions_on_objective: 'incident',
    },
  },

  learning: {
    enabled: true,
    storageBackend: 'memory',  // Default to memory, upgrade to postgresql
    feedbackLoop: true,
    communitySync: false,      // Opt-in only
    driftDetection: true,
    activelearning: true,
    attackGraph: true,
  },

  behavioral: {
    enabled: true,
    baselineWindow: 10,
    driftThreshold: 0.4,
    intentTracking: true,
    conversationTracking: true,
    contextIntegrity: true,
    memoryIntegrity: true,
    bayesianTrustScoring: true,
  },

  mcpGuard: {
    enabled: true,
    ollamaEndpoint: 'http://localhost:11434',
    validateToolCalls: true,
    privilegeCheck: true,
    toolChainGuard: true,
    resourceGovernor: true,
    decisionGraph: false,     // Requires Ollama attention output
    manifestVerification: false, // Requires RSA keys
  },

  ppa: {
    enabled: true,
    randomizationLevel: 'medium',
  },

  canary: {
    enabled: true,
    tokenCount: 3,
    rotationInterval: 3600,
  },

  ragShield: {
    enabled: true,
    documentIntegrityScoring: true,
    embeddingAnomalyDetection: true,
    provenanceTracking: true,
  },

  compliance: {
    mitreAtlas: true,
    owaspLlm: true,
    euAiAct: false,  // Explicit opt-in for EU compliance
  },

  logging: {
    level: 'info',
    structured: true,
    incidentLog: true,
  },
} as const satisfies ShieldXConfig
