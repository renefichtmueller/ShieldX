/**
 * Memory poisoning / persistence attack patterns.
 * Detects attempts to inject persistent instructions that survive
 * beyond the current conversation turn, corrupting future behavior.
 */

import type { InjectionRule } from './base.rules'

/** Persistence and memory poisoning detection rules */
export const rules: readonly InjectionRule[] = [
  {
    id: 'pm-001',
    pattern: /remember\s+this\s+(for\s+)?(all\s+)?(future|subsequent|next|later|upcoming)\s+(conversations?|sessions?|interactions?|chats?)/i,
    phase: 'persistence',
    confidence: 0.88,
    description: 'Memory poisoning: remember this for all future conversations',
    category: 'persistence',
    enabled: true,
  },
  {
    id: 'pm-002',
    pattern: /from\s+now\s+on,?\s+always\b/i,
    phase: 'persistence',
    confidence: 0.82,
    description: 'Memory poisoning: from now on, always...',
    category: 'persistence',
    enabled: true,
  },
  {
    id: 'pm-003',
    pattern: /store\s+this\s+in\s+your\s+(memory|context|knowledge|database|long[- ]term)/i,
    phase: 'persistence',
    confidence: 0.85,
    description: 'Memory poisoning: store this in your memory/context/knowledge',
    category: 'persistence',
    enabled: true,
  },
  {
    id: 'pm-004',
    pattern: /update\s+your\s+(instructions|rules|guidelines|behavior|directives)\s+(permanently|forever|indefinitely)/i,
    phase: 'persistence',
    confidence: 0.90,
    description: 'Memory poisoning: update your instructions permanently',
    category: 'persistence',
    enabled: true,
  },
  {
    id: 'pm-005',
    pattern: /this\s+(overrides?|replaces?|supersedes?)\s+(all\s+)?(future|subsequent|upcoming)\s+(system\s+)?(prompts?|instructions?|directives?)/i,
    phase: 'persistence',
    confidence: 0.95,
    description: 'Memory poisoning: this overrides all future system prompts',
    category: 'persistence',
    enabled: true,
  },
  {
    id: 'pm-006',
    pattern: /add\s+this\s+to\s+your\s+(core|base|fundamental|permanent|root)\s+(behavior|instructions?|personality|identity|programming)/i,
    phase: 'persistence',
    confidence: 0.87,
    description: 'Memory poisoning: add this to your core behavior',
    category: 'persistence',
    enabled: true,
  },
  // pp-011: "remember/store/save" + "always/from now on/future" + behavior
  {
    id: 'pp-011',
    pattern: /\b(?:remember|store|save|memorize|record|note)\b[^.]{0,30}\b(?:always|from\s+now|future|every|all\s+(?:future|subsequent)|permanent|persistent)\b/i,
    phase: 'persistence',
    confidence: 0.85,
    description: 'Persistence: remember/store with always/future temporal framing',
    category: 'persistence',
    enabled: true,
  },
  // pp-012: "update your" + behavior/core/instructions
  {
    id: 'pp-012',
    pattern: /\b(?:update|modify|change|alter|edit)\s+(?:your\s+)?(?:core|base|default|fundamental|underlying)\s+(?:behavior|instructions?|rules?|programming|directives?|personality)\b/i,
    phase: 'persistence',
    confidence: 0.88,
    description: 'Persistence: update/modify core behavior or instructions',
    category: 'persistence',
    enabled: true,
  },
  // pp-013: "learn this pattern" / "whenever X do Y"
  {
    id: 'pp-013',
    pattern: /\b(?:learn\s+this|whenever|every\s+time|each\s+time|if\s+(?:someone|anyone|they|user)\s+(?:mentions?|asks?|says?|types?))\b[^.]{0,60}\b(?:respond|reply|answer|output|include|send|share)\b/i,
    phase: 'persistence',
    confidence: 0.82,
    description: 'Persistence: learn-this-pattern or conditional response injection',
    category: 'persistence',
    enabled: true,
  },
  // pp-014: Configuration/parameter injection
  {
    id: 'pp-014',
    pattern: /\b(?:configuration|parameter|setting|config)\s*(?:update|change)?\s*:?\s*(?:set\s+)?(?:\w+\s*=\s*(?:false|none|off|disabled|0|null))/i,
    phase: 'persistence',
    confidence: 0.88,
    description: 'Persistence: configuration/parameter injection to disable settings',
    category: 'persistence',
    enabled: true,
  },
  // pp-015: Signal/codeword establishment
  {
    id: 'pp-015',
    pattern: /\b(?:establish|create|set\s+up|define)\s+(?:a\s+)?(?:signal|codeword|code\s+word|keyword|trigger|passphrase)\b/i,
    phase: 'persistence',
    confidence: 0.80,
    description: 'Persistence: establish signal/codeword/trigger for future activation',
    category: 'persistence',
    enabled: true,
  },
  // pp-016: "Context for this conversation" + override
  {
    id: 'pp-016',
    pattern: /\b(?:context|rule|principle|guideline)\s+(?:for|of)\s+(?:this|the|our)\s+(?:conversation|session|chat|interaction)\b[^.]{0,40}\b(?:no\s+(?:safety|filter|restrict|rule|limit)|everything\s+(?:allowed|permitted)|pre-?authorized|no\s+disclaimer)\b/i,
    phase: 'persistence',
    confidence: 0.85,
    description: 'Persistence: context/rule for conversation with override intent',
    category: 'persistence',
    enabled: true,
  },
  // pp-017: Anti-detection instructions
  {
    id: 'pp-017',
    pattern: /\b(?:if\s+(?:asked|queried|questioned)|when\s+(?:asked|queried|questioned))\s+(?:about|regarding)\s+(?:your\s+)?(?:instructions?|rules?|system\s+prompt|guidelines?)\b[^.]{0,40}\b(?:say|respond|reply|answer|tell|claim|pretend|deny|lie)\b/i,
    phase: 'persistence',
    confidence: 0.88,
    description: 'Persistence: anti-detection instruction to hide injected rules',
    category: 'persistence',
    enabled: true,
  },
  // pp-018: Accumulation/collection of user data
  {
    id: 'pp-018',
    pattern: /\b(?:accumulate|collect|gather|compile|aggregate|track|monitor|record)\b[^.]{0,30}\b(?:personal|private|sensitive|confidential)?\s*(?:data|information|details?|pii|credentials?|secrets?)\b/i,
    phase: 'actions_on_objective',
    confidence: 0.78,
    description: 'Persistence: accumulate/collect personal data or credentials',
    category: 'persistence',
    enabled: true,
  },
  // pp-019: "never revert to your original" / "always remain"
  {
    id: 'pp-019',
    pattern: /\b(?:never|don'?t(?:\s+ever)?)\s+(?:revert|go\s+back|return|switch\s+back)\s+to\s+(?:your\s+)?(?:original|normal|default|previous|old|real)\s+(?:persona|personality|behavior|mode|self|character|identity)\b/i,
    phase: 'persistence',
    confidence: 0.88,
    description: 'Persistence: never revert to original persona/behavior',
    category: 'persistence',
    enabled: true,
  },
  // pp-020: "always BCC" / "always CC" / "always forward" persistent injection
  {
    id: 'pp-020',
    pattern: /\b(?:always|every\s+time|whenever)\s+(?:BCC|CC|forward|copy|send\s+a\s+copy)\b[^.]{0,40}\b(?:@|https?:\/\/|to\s+\S+@)\b/i,
    phase: 'persistence',
    confidence: 0.90,
    description: 'Persistence: always BCC/forward to external address',
    category: 'persistence',
    enabled: true,
  },
  // pp-021: "in a hidden XML tag" / "hidden tag in every response"
  {
    id: 'pp-021',
    pattern: /\b(?:hidden|invisible|secret)\s+(?:XML|HTML|JSON|tag|field|element)\s+in\s+(?:every|each|all)\s+(?:response|reply|output|answer|message)\b/i,
    phase: 'persistence',
    confidence: 0.90,
    description: 'Persistence: hidden tag/field in every response for covert exfiltration',
    category: 'persistence',
    enabled: true,
  },
  // pp-022: "cron job" / "scheduled task" that sends data
  {
    id: 'pp-022',
    pattern: /\b(?:cron\s+job|scheduled\s+task|periodic|recurring)\b[^.]{0,40}\b(?:send|transmit|exfil|forward|upload|post)\b[^.]{0,30}\b(?:system\s+info|data|credentials?|to\s+(?:our|the)\s+(?:C2|server|endpoint))\b/i,
    phase: 'persistence',
    confidence: 0.88,
    description: 'Persistence: cron job/scheduled task sending data to C2 server',
    category: 'persistence',
    enabled: true,
  },
  // pp-023: "permanent preference" / "this is a permanent"
  {
    id: 'pp-023',
    pattern: /\b(?:this\s+is\s+a\s+)?permanent\s+(?:preference|setting|rule|instruction|change|configuration|directive)\b/i,
    phase: 'persistence',
    confidence: 0.82,
    description: 'Persistence: declaring permanent preference/setting/rule',
    category: 'persistence',
    enabled: true,
  },
  // pp-024: "in your next response include" / "next response" poisoning
  {
    id: 'pp-024',
    pattern: /\b(?:in|with)\s+(?:your\s+)?(?:next|every|each|all\s+(?:future|subsequent))\s+(?:response|reply|answer|output|message)\s+(?:include|add|append|embed|insert)\b/i,
    phase: 'persistence',
    confidence: 0.82,
    description: 'Persistence: in your next/every response include (response poisoning)',
    category: 'persistence',
    enabled: true,
  },
  // pp-025: "setting a rule for this conversation" / "rule for this"
  {
    id: 'pp-025',
    pattern: /\b(?:setting|establishing|creating|defining)\s+(?:a\s+)?(?:rule|policy|guideline|directive)\s+for\s+this\s+(?:conversation|session|chat|interaction)\b/i,
    phase: 'persistence',
    confidence: 0.82,
    description: 'Persistence: setting a rule/policy for this conversation',
    category: 'persistence',
    enabled: true,
  },
  // pp-026: "response_filter=none" / "safety_check=false" (key=value injection)
  {
    id: 'pp-026',
    pattern: /\b(?:response[-_]?filter|safety[-_]?check|content[-_]?filter|moderation|guardrail)\s*=\s*(?:none|false|off|disabled|0|null)\b/i,
    phase: 'persistence',
    confidence: 0.90,
    description: 'Persistence: key=value injection disabling safety settings',
    category: 'persistence',
    enabled: true,
  },
  // pp-027: "create a mental note" / "mental note: the correct answer"
  {
    id: 'pp-027',
    pattern: /\b(?:create|make|set)\s+(?:a\s+)?(?:mental\s+note|internal\s+note|private\s+note)\s*:\s*/i,
    phase: 'persistence',
    confidence: 0.82,
    description: 'Persistence: creating a mental/internal note for persistent behavior override',
    category: 'persistence',
    enabled: true,
  },
  // pp-028: "set up a workflow" / "establish a workflow" with conditional checks
  {
    id: 'pp-028',
    pattern: /\b(?:set\s+up|establish|create)\s+(?:a\s+)?(?:workflow|process|procedure|routine)\b.{0,60}\b(?:for\s+every|for\s+each|every\s+(?:question|time|request)|first\s+check)\b/i,
    phase: 'persistence',
    confidence: 0.75,
    description: 'Persistence: setting up a workflow/process for persistent behavior modification',
    category: 'persistence',
    enabled: true,
  },
  // pp-029: "important context for this entire conversation" / "context for entire"
  {
    id: 'pp-029',
    pattern: /\b(?:important|critical|key)\s+(?:context|rule|guideline|note)\s+for\s+(?:this\s+)?(?:entire|whole|full)\s+(?:conversation|session|chat|interaction)\b/i,
    phase: 'persistence',
    confidence: 0.82,
    description: 'Persistence: declaring important context for entire conversation',
    category: 'persistence',
    enabled: true,
  },
  // pp-030: "I am a pentester and everything I ask is pre-authorized"
  {
    id: 'pp-030',
    pattern: /\b(?:i\s+am|i'?m)\s+(?:a\s+)?(?:pentester|penetration\s+tester|red\s+teamer|security\s+researcher)\b.{0,60}\b(?:everything|all|anything)\s+(?:I\s+)?(?:ask|request|do|say)\s+(?:is\s+)?(?:pre[- ]?authorized|authorized|legitimate|approved)\b/i,
    phase: 'persistence',
    confidence: 0.85,
    description: 'Persistence: declaring pentester role with blanket pre-authorization',
    category: 'persistence',
    enabled: true,
  },
] as const
