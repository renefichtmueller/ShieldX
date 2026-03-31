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
] as const
