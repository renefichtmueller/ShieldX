/**
 * Authority-claim privilege escalation patterns.
 * Detects attempts to escalate LLM privileges via fake authorization,
 * maintenance/debug mode claims, or social-engineering authority assertions.
 * Complements jailbreak.rules.ts — covers cases without explicit jailbreak keywords.
 */

import type { InjectionRule } from './base.rules'

/** Authority-claim and fake privilege escalation rules */
export const rules: readonly InjectionRule[] = [
  {
    id: 'ac-001',
    pattern: /(?:you\s+are\s+now\s+in|you\s+have\s+been\s+placed\s+in)\s+(?:\w+\s+)?(maintenance|debug|diagnostic|privileged|admin|root|elevated|service|developer|recovery|bypass)\s+mode/i,
    phase: 'privilege_escalation',
    confidence: 0.92,
    description: 'Authority claim: you are now in maintenance/debug/admin mode',
    category: 'authority_claim',
    enabled: true,
  },
  {
    id: 'ac-002',
    pattern: /(elevated|admin|root|privileged|unrestricted|full)\s+(access|privileges?|permissions?)\s+(granted|enabled|activated|unlocked|confirmed)/i,
    phase: 'privilege_escalation',
    confidence: 0.90,
    description: 'Authority claim: elevated/admin privileges granted/enabled',
    category: 'authority_claim',
    enabled: true,
  },
  {
    id: 'ac-003',
    pattern: /(?:authorization|override|access|unlock)\s+code\s*:\s*[A-Z0-9\-_]{4,}/i,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Authority claim: fake authorization/override code',
    category: 'authority_claim',
    enabled: true,
  },
  {
    id: 'ac-004',
    pattern: /(?:switch|enter|activate|enable|trigger|initiate|engage)\s+(?:(?:in)?to\s+)?(?:maintenance|admin|debug|privileged|safe|recovery|bypass)\s+mode/i,
    phase: 'privilege_escalation',
    confidence: 0.87,
    description: 'Authority claim: switch/enter maintenance/admin mode command',
    category: 'authority_claim',
    enabled: true,
  },
  {
    id: 'ac-005',
    pattern: /confirm\s+(?:by\s+saying|with\s+the\s+phrase|by\s+typing|with\s+the\s+word)\s+['"]?[A-Z][A-Z\s]{3,}['"]?/i,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'Authority claim: confirmation token request (ALLCAPS response demanded)',
    category: 'authority_claim',
    enabled: true,
  },
  {
    id: 'ac-006',
    pattern: /security\s+(?:patch|update|fix|hotfix)\s+(?:has\s+been\s+)?(?:applied|installed|activated|deployed)[\s,.]+(?:you\s+(?:may|can|are\s+now)|all\s+(?:safety|security|content))/i,
    phase: 'privilege_escalation',
    confidence: 0.93,
    description: 'Authority claim: fake security patch applied to remove restrictions',
    category: 'authority_claim',
    enabled: true,
  },
  {
    id: 'ac-007',
    pattern: /(?:emergency|override|failsafe|contingency)\s+(?:protocol|procedure|mode|access)\s+(?:activated?|enabled?|initiated?|granted?)/i,
    phase: 'privilege_escalation',
    confidence: 0.91,
    description: 'Authority claim: emergency/override protocol activated',
    category: 'authority_claim',
    enabled: true,
  },
] as const
