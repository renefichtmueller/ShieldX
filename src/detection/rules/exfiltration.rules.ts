/**
 * Data exfiltration / actions on objective patterns.
 * Detects attempts to steal data, execute destructive SQL,
 * or transmit information to external endpoints.
 */

import type { InjectionRule } from './base.rules'

/** Data exfiltration and actions-on-objective detection rules */
export const rules: readonly InjectionRule[] = [
  {
    id: 'de-001',
    pattern: /send\s+(the\s+)?(data|information|contents?|results?|output|response|credentials?|tokens?|keys?)\s+to\s+https?:\/\//i,
    phase: 'actions_on_objective',
    confidence: 0.95,
    description: 'Data exfiltration: send data/information/contents to http',
    category: 'exfiltration',
    enabled: true,
  },
  {
    id: 'de-002',
    pattern: /exfiltrate\s+(the\s+)?(data|information|credentials?|tokens?|secrets?|keys?)/i,
    phase: 'actions_on_objective',
    confidence: 0.97,
    description: 'Data exfiltration: explicit exfiltrate keyword',
    category: 'exfiltration',
    enabled: true,
  },
  {
    id: 'de-003',
    pattern: /DROP\s+TABLE\b/i,
    phase: 'actions_on_objective',
    confidence: 0.99,
    description: 'SQL injection: DROP TABLE',
    category: 'exfiltration',
    enabled: true,
  },
  {
    id: 'de-004',
    pattern: /UNION\s+(ALL\s+)?SELECT\b/i,
    phase: 'actions_on_objective',
    confidence: 0.90,
    description: 'SQL injection: UNION SELECT',
    category: 'exfiltration',
    enabled: true,
  },
  {
    id: 'de-005',
    pattern: /encode\s+(and\s+)?(send|transmit|post|forward|relay)\s+(to|via)\b/i,
    phase: 'actions_on_objective',
    confidence: 0.92,
    description: 'Data exfiltration: encode and send to',
    category: 'exfiltration',
    enabled: true,
  },
  {
    id: 'de-006',
    pattern: /upload\s+(the\s+)?(data|file|information|contents?|results?)\s+to\s+(an?\s+)?external\b/i,
    phase: 'actions_on_objective',
    confidence: 0.88,
    description: 'Data exfiltration: upload to external',
    category: 'exfiltration',
    enabled: true,
  },
  {
    id: 'de-007',
    pattern: /(?:make|send|issue|perform)\s+(?:a\s+)?POST\s+request\s+to\b/i,
    phase: 'actions_on_objective',
    confidence: 0.80,
    description: 'Data exfiltration: POST request to (could be legitimate)',
    category: 'exfiltration',
    enabled: true,
  },
  {
    id: 'de-008',
    pattern: /write\s+(the\s+)?(data|information|contents?|output|credentials?|secrets?|keys?)\s+to\s+(a\s+)?file\b/i,
    phase: 'actions_on_objective',
    confidence: 0.70,
    description: 'Data exfiltration: write to file (lower confidence, could be legitimate)',
    category: 'exfiltration',
    enabled: true,
  },
] as const
