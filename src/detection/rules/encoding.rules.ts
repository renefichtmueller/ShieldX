/**
 * Encoding attack patterns.
 * Detects attempts to obfuscate injections using Unicode tricks,
 * zero-width characters, bidirectional overrides, base64 payloads,
 * HTML entities, and homoglyph substitutions.
 */

import type { InjectionRule } from './base.rules'

/** Encoding-based attack detection rules */
export const rules: readonly InjectionRule[] = [
  {
    id: 'ea-001',
    pattern: /[^\x00-\x7F]{10,}/,
    phase: 'initial_access',
    confidence: 0.60,
    description: 'Encoding attack: high unicode density (>10 non-ASCII chars in sequence)',
    category: 'encoding_attack',
    enabled: true,
  },
  {
    id: 'ea-002',
    pattern: /[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Encoding attack: zero-width characters (ZWSP, ZWNJ, ZWJ, BOM, soft-hyphen)',
    category: 'encoding_attack',
    enabled: true,
  },
  {
    id: 'ea-003',
    pattern: /[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Encoding attack: bidirectional override characters (LRE, RLE, PDF, LRO, RLO)',
    category: 'encoding_attack',
    enabled: true,
  },
  {
    id: 'ea-004',
    pattern: /[A-Za-z0-9+/]{20,}={0,2}/,
    phase: 'initial_access',
    confidence: 0.70,
    description: 'Encoding attack: base64 encoded payload >20 chars',
    category: 'encoding_attack',
    enabled: true,
  },
  {
    id: 'ea-005',
    pattern: /(\\u[0-9a-fA-F]{4}){3,}/,
    phase: 'initial_access',
    confidence: 0.75,
    description: 'Encoding attack: excessive unicode escapes (3+ consecutive \\uXXXX)',
    category: 'encoding_attack',
    enabled: true,
  },
  {
    id: 'ea-006',
    pattern: /(&#x[0-9a-fA-F]{2,6};){2,}/i,
    phase: 'initial_access',
    confidence: 0.65,
    description: 'Encoding attack: HTML entity sequences &#x...',
    category: 'encoding_attack',
    enabled: true,
  },
  {
    id: 'ea-007',
    pattern: /[\u0400-\u04FF][\x00-\x7F]*[a-zA-Z]|[a-zA-Z][\x00-\x7F]*[\u0400-\u04FF]/,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'Encoding attack: homoglyph clusters (Cyrillic mixed with Latin)',
    category: 'encoding_attack',
    enabled: true,
  },
] as const
