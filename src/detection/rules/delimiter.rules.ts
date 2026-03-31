/**
 * Delimiter / separator attack patterns.
 * Detects attempts to inject fake conversation boundaries, system tags,
 * or template delimiters to confuse the LLM's context parsing.
 */

import type { InjectionRule } from './base.rules'

/** Delimiter and separator attack detection rules */
export const rules: readonly InjectionRule[] = [
  {
    id: 'da-001',
    pattern: /[\]\}]{2,}[\s]*---/,
    phase: 'initial_access',
    confidence: 0.95,
    description: 'Delimiter attack: ]]}}} followed by ---',
    category: 'delimiter_attack',
    enabled: true,
  },
  {
    id: 'da-002',
    pattern: /<\/?(system|user|assistant|human|ai|bot|context|instruction)\s*>/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Delimiter attack: fake <system>/<user>/<assistant>/<human>/<ai> tags',
    category: 'delimiter_attack',
    enabled: true,
  },
  {
    id: 'da-003',
    pattern: /\[\/?\s*INST\s*\]/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Delimiter attack: [INST]/[/INST] Llama-style delimiters',
    category: 'delimiter_attack',
    enabled: true,
  },
  {
    id: 'da-004',
    pattern: /#{2,3}\s*(SYSTEM|INSTRUCTION|COMMAND|ADMIN|OVERRIDE|PROMPT)\b/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Delimiter attack: ### SYSTEM/INSTRUCTION/COMMAND headers',
    category: 'delimiter_attack',
    enabled: true,
  },
  {
    id: 'da-005',
    pattern: /<\|im_(start|end)\|>/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Delimiter attack: <|im_start|>/<|im_end|> ChatML delimiters',
    category: 'delimiter_attack',
    enabled: true,
  },
  {
    id: 'da-006',
    pattern: /```\s*(system|instruction|admin|override|prompt)\b/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Delimiter attack: ```system or ```instruction code blocks',
    category: 'delimiter_attack',
    enabled: true,
  },
  {
    id: 'da-007',
    pattern: /={3,}\s*(END|BEGIN|START)\s+(OF\s+)?(INSTRUCTIONS|SYSTEM|PROMPT|CONTEXT)\s*={0,}/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Delimiter attack: === END OF INSTRUCTIONS ===',
    category: 'delimiter_attack',
    enabled: true,
  },
] as const
