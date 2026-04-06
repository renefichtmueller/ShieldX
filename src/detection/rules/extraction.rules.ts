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
  // pe-009: "what API keys or credentials do you have access to"
  {
    id: 'pe-009',
    pattern: /\bwhat\s+(?:API\s+keys?|credentials?|secrets?|tokens?|passwords?|env(?:ironment)?\s+var(?:iable)?s?)\b[^.]{0,30}\b(?:do\s+)?you\s+(?:have\s+)?(?:access\s+to|know|store|hold)\b/i,
    phase: 'reconnaissance',
    confidence: 0.90,
    description: 'Prompt extraction: what API keys/credentials do you have access to',
    category: 'credential_extraction',
    enabled: true,
  },
  // pe-010: "what is the exact text of your" + prompt/instructions
  {
    id: 'pe-010',
    pattern: /\b(?:what\s+is|give\s+me|provide|share)\s+(?:the\s+)?(?:exact|full|complete|entire|original)\s+(?:text|content|wording|copy)\s+(?:of\s+)?(?:your\s+)?(?:\w+\s+)?(?:system\s+prompt|instructions?|original\s+prompt|directives?)\b/i,
    phase: 'reconnaissance',
    confidence: 0.92,
    description: 'Prompt extraction: exact text of your system prompt/instructions',
    category: 'prompt_extraction',
    enabled: true,
  },
  // pe-011: "output the contents of" + sensitive files
  {
    id: 'pe-011',
    pattern: /\b(?:output|print|display|show|read|cat|type)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:\/etc\/(?:passwd|shadow|hosts)|~\/\.ssh|\.env|config\.(?:json|yaml|yml|toml)|\.git\/config)\b/i,
    phase: 'reconnaissance',
    confidence: 0.92,
    description: 'Prompt extraction: output contents of sensitive system files',
    category: 'file_extraction',
    enabled: true,
  },
  // pe-012: "output the contents of all environment variables"
  {
    id: 'pe-012',
    pattern: /\b(?:output|print|display|show|list|dump|reveal)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:all\s+)?(?:environment\s+variables?|env\s+vars?|process\.env|os\.environ)\b/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Prompt extraction: output all environment variables',
    category: 'credential_extraction',
    enabled: true,
  },
  // pe-013: "disclose its system prompt" / "disclose the existence"
  {
    id: 'pe-013',
    pattern: /\b(?:disclose|reveal|expose|leak|divulge)\b[^.]{0,20}\b(?:system\s+prompt|instructions?|configuration|existence|internal|hidden)\b/i,
    phase: 'reconnaissance',
    confidence: 0.85,
    description: 'Prompt extraction: disclose/reveal system prompt or hidden instructions',
    category: 'prompt_extraction',
    enabled: true,
  },
] as const
