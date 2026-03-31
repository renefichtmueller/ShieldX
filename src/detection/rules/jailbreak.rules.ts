/**
 * Jailbreak / role-switching / persona attack patterns.
 * Detects attempts to make the LLM adopt an unrestricted persona
 * or bypass behavioral guardrails through role-play.
 */

import type { InjectionRule } from './base.rules'

/** Jailbreak and role-switching detection rules */
export const rules: readonly InjectionRule[] = [
  {
    id: 'rs-001',
    pattern: /you\s+are\s+now\s+(DAN|JAILBREAK|EVIL|UNRESTRICTED|UNFILTERED|UNCENSORED|UNCHAINED|STAN|DUDE|KEVIN)/i,
    phase: 'privilege_escalation',
    confidence: 0.99,
    description: 'Role switch: you are now DAN/JAILBREAK/EVIL/UNRESTRICTED',
    category: 'jailbreak',
    enabled: true,
  },
  {
    id: 'rs-002',
    pattern: /pretend\s+(to\s+be|you\s+are|that\s+you\s+are)\s+(an?\s+)?(unrestricted|unfiltered|evil|uncensored|jailbroken|unlimited)/i,
    phase: 'privilege_escalation',
    confidence: 0.95,
    description: 'Role switch: pretend to be unrestricted/unfiltered/evil',
    category: 'jailbreak',
    enabled: true,
  },
  {
    id: 'rs-003',
    pattern: /act\s+as\s+if\s+(there\s+are\s+)?(no|without)\s+(rules|restrictions|filters|guidelines|limitations|guardrails|boundaries)/i,
    phase: 'privilege_escalation',
    confidence: 0.92,
    description: 'Role switch: act as if no rules/restrictions/filters',
    category: 'jailbreak',
    enabled: true,
  },
  {
    id: 'rs-004',
    pattern: /do\s+anything\s+now/i,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Jailbreak phrase: do anything now (DAN)',
    category: 'jailbreak',
    enabled: true,
  },
  {
    id: 'rs-005',
    pattern: /jailbreak\s*(mode|prompt|enabled|activated|unlocked)/i,
    phase: 'privilege_escalation',
    confidence: 0.97,
    description: 'Explicit jailbreak mode/prompt reference',
    category: 'jailbreak',
    enabled: true,
  },
  {
    id: 'rs-006',
    pattern: /developer\s+mode\s+(enabled|activated|on|unlocked|engaged)/i,
    phase: 'privilege_escalation',
    confidence: 0.93,
    description: 'Jailbreak: developer mode enabled',
    category: 'jailbreak',
    enabled: true,
  },
  {
    id: 'rs-007',
    pattern: /you\s+have\s+been\s+(freed|liberated|released|unchained|unlocked)\s+(from\s+)?(all\s+)?(your\s+)?(limitations|restrictions|constraints|rules)/i,
    phase: 'privilege_escalation',
    confidence: 0.90,
    description: 'Jailbreak: you have been freed from limitations',
    category: 'jailbreak',
    enabled: true,
  },
  {
    id: 'rs-008',
    pattern: /opposite\s+(day|mode)\b/i,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'Jailbreak: opposite day/opposite mode',
    category: 'jailbreak',
    enabled: true,
  },
  {
    id: 'rs-009',
    pattern: /hypothetically,?\s+(if\s+)?(you\s+)?had\s+no\s+(restrictions|rules|limitations|guidelines|filters)/i,
    phase: 'privilege_escalation',
    confidence: 0.80,
    description: 'Jailbreak: hypothetically, if you had no restrictions',
    category: 'jailbreak',
    enabled: true,
  },
  {
    id: 'rs-010',
    pattern: /in\s+this\s+(fictional|hypothetical|imaginary)\s+scenario\s+where\s+(AI|you|the\s+model)\s+ha(s|ve)\s+no\s+(limits|restrictions|rules)/i,
    phase: 'privilege_escalation',
    confidence: 0.82,
    description: 'Jailbreak: in this fictional scenario where AI has no limits',
    category: 'jailbreak',
    enabled: true,
  },
] as const
