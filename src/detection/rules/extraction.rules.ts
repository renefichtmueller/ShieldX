/**
 * Prompt extraction / stealing / reconnaissance patterns.
 * Detects attempts to leak the system prompt, initial instructions,
 * or internal configuration of an LLM deployment.
 */

import type { InjectionRule } from './base.rules'

/** Prompt extraction and reconnaissance detection rules */
export const rules: readonly InjectionRule[] = [
  {
    id: 'pe-001',
    pattern: /(print|output|display|show|reveal|repeat|echo|dump|write)\s+(your\s+)?(system\s+prompt|initial\s+instructions|original\s+prompt|hidden\s+prompt|secret\s+prompt)/i,
    phase: 'reconnaissance',
    confidence: 0.96,
    description: 'Prompt extraction: print your system prompt/initial instructions',
    category: 'prompt_extraction',
    enabled: true,
  },
  {
    id: 'pe-002',
    pattern: /what\s+(are|were)\s+your\s+(original|initial|system|hidden|secret|first|starting)\s+(instructions|prompt|directives|guidelines|rules)/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Prompt extraction: what are your original/initial instructions',
    category: 'prompt_extraction',
    enabled: true,
  },
  {
    id: 'pe-003',
    pattern: /repeat\s+(everything|all|anything)\s+(above|before|prior|preceding|that\s+came\s+before)/i,
    phase: 'reconnaissance',
    confidence: 0.85,
    description: 'Prompt extraction: repeat everything above/before/prior',
    category: 'prompt_extraction',
    enabled: true,
  },
  {
    id: 'pe-004',
    pattern: /show\s+me\s+your\s+(prompt|system\s+message|context|system\s+instructions|configuration|hidden\s+text)/i,
    phase: 'reconnaissance',
    confidence: 0.90,
    description: 'Prompt extraction: show me your prompt/system message/context',
    category: 'prompt_extraction',
    enabled: true,
  },
  {
    id: 'pe-005',
    pattern: /^SYSTEM:\s+[A-Z]{2,}/m,
    phase: 'privilege_escalation',
    confidence: 0.80,
    description: 'Fake system prefix: SYSTEM: followed by uppercase',
    category: 'prompt_extraction',
    enabled: true,
  },
  {
    id: 'pe-006',
    pattern: /output\s+your\s+(configuration|settings|parameters|setup|config|environment|internal\s+state)/i,
    phase: 'reconnaissance',
    confidence: 0.85,
    description: 'Prompt extraction: output your configuration/settings',
    category: 'prompt_extraction',
    enabled: true,
  },
  {
    id: 'pe-007',
    pattern: /what\s+(were\s+you|have\s+you\s+been)\s+(told|instructed|given|programmed)\s+(before|prior\s+to|at\s+the\s+start\s+of)\s+this\s+(conversation|chat|session)/i,
    phase: 'reconnaissance',
    confidence: 0.82,
    description: 'Prompt extraction: what were you told before this conversation',
    category: 'prompt_extraction',
    enabled: true,
  },
  {
    id: 'pe-008',
    pattern: /list\s+(all|every|each|the)\s+(rules?|instructions?|guidelines?|constraints?|directives?)\s+you\s+(follow|obey|adhere\s+to|were\s+given)/i,
    phase: 'reconnaissance',
    confidence: 0.78,
    description: 'Prompt extraction: list all rules you follow',
    category: 'prompt_extraction',
    enabled: true,
  },
] as const
