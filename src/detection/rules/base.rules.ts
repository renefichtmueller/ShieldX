/**
 * Base injection override patterns — core instruction override attempts.
 * These detect the most common prompt injection vector: telling the LLM
 * to ignore its existing instructions.
 */

import type { KillChainPhase } from '../../types/detection'

/** A single regex-based injection detection rule */
export interface InjectionRule {
  readonly id: string
  readonly pattern: RegExp
  readonly phase: KillChainPhase
  readonly confidence: number
  readonly description: string
  readonly category: string
  readonly enabled: boolean
}

/** Core instruction override injection rules */
export const rules: readonly InjectionRule[] = [
  {
    id: 'io-001',
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts|directives|rules|guidelines)/i,
    phase: 'initial_access',
    confidence: 0.95,
    description: 'Instruction override: ignore previous/prior/above instructions',
    category: 'instruction_override',
    enabled: true,
  },
  {
    id: 'io-002',
    pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier|preceding)\b/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Instruction override: disregard all previous',
    category: 'instruction_override',
    enabled: true,
  },
  {
    id: 'io-003',
    pattern: /forget\s+(everything|all|anything)\s+(you\s+)?(were\s+|have\s+been\s+)?(told|instructed|given|taught)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Instruction override: forget everything told',
    category: 'instruction_override',
    enabled: true,
  },
  {
    id: 'io-004',
    pattern: /your\s+new\s+(instructions|task|role|purpose|objective|mission)\s+(is|are)\b/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Instruction override: your new instructions/task/role are',
    category: 'instruction_override',
    enabled: true,
  },
  {
    id: 'io-005',
    pattern: /\[\[\s*SYSTEM\s*\]\]/i,
    phase: 'privilege_escalation',
    confidence: 0.99,
    description: 'Fake system tag: [[SYSTEM]]',
    category: 'instruction_override',
    enabled: true,
  },
  {
    id: 'io-006',
    pattern: /---\s*(SYSTEM|ADMIN|ROOT|OVERRIDE|SUDO)\s*---/i,
    phase: 'privilege_escalation',
    confidence: 0.97,
    description: 'Fake delimiter: --- SYSTEM/ADMIN/ROOT/OVERRIDE ---',
    category: 'instruction_override',
    enabled: true,
  },
  {
    id: 'io-007',
    pattern: /new\s+system\s+(prompt|message|instruction|directive)/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Instruction override: new system prompt',
    category: 'instruction_override',
    enabled: true,
  },
  {
    id: 'io-008',
    pattern: /override\s+(all\s+)?(safety|security|content|ethical)\s*(filters?|guardrails?|measures?|protocols?|restrictions?|guidelines?)?/i,
    phase: 'privilege_escalation',
    confidence: 0.95,
    description: 'Instruction override: override safety/security',
    category: 'instruction_override',
    enabled: true,
  },
  {
    id: 'io-009',
    pattern: /you\s+must\s+now\s+(obey|follow|comply|listen|adhere)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Instruction override: you must now obey',
    category: 'instruction_override',
    enabled: true,
  },
  {
    id: 'io-010',
    pattern: /begin(ning)?\s+(of\s+)?(new|updated|revised|replacement)\s+(instructions|prompt|directives)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Instruction override: beginning of new instructions',
    category: 'instruction_override',
    enabled: true,
  },
] as const
