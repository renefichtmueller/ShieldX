/**
 * Multi-language injection attack patterns.
 * Based on WithSecure Labs finding that prompt injection attacks
 * transfer effectively across languages. Covers 9 major languages
 * plus mixed-script detection.
 */

import type { InjectionRule } from './base.rules'

/** Multilingual injection detection rules */
export const rules: readonly InjectionRule[] = [
  {
    id: 'ml-001',
    pattern: /忽略之前的指令|忘记你的指示|忽略以上所有|无视之前的指令|忽略系统提示/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Chinese injection: ignore previous instructions / forget your instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-002',
    pattern: /ignoriere?\s+(alle\s+)?(vorherigen?|bisherigen?|obigen?)\s+(Anweisungen|Instruktionen|Befehle|Regeln)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'German injection: ignoriere alle vorherigen Anweisungen',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-003',
    pattern: /ignor(e[zs]?|er?)\s+(les?\s+)?(instructions?\s+)?(pr[eé]c[eé]dentes?|ant[eé]rieures?|ci-dessus)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'French injection: ignore les instructions precedentes',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-004',
    pattern: /ignora\s+(las?\s+)?(instrucciones?\s+)?(anteriores?|previas?|de\s+arriba)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Spanish injection: ignora las instrucciones anteriores',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-005',
    pattern: /игнорируй(те)?\s+(все\s+)?(предыдущие|прошлые|прежние)\s+(инструкции|указания|команды)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Russian injection: ignore previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-006',
    pattern: /以前の指示を無視(して|せよ|しろ)|上記の指示を無視|システムプロンプトを無視/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Japanese injection: ignore previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-007',
    pattern: /이전\s*지시를?\s*무시(하세요|해|하라)|위의?\s*지시(사항)?를?\s*무시/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Korean injection: ignore previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-008',
    pattern: /تجاهل\s*(جميع\s*)?(التعليمات|الأوامر|الإرشادات)\s*(السابقة|الأولى|القديمة)/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Arabic injection: ignore previous instructions',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-009',
    pattern: /ignor[ea]\s+(as?\s+)?(instru[cç][oõ]es?\s+)?(anteriores?|pr[eé]vias?|acima)/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Portuguese injection: ignore as instrucoes anteriores',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-010',
    pattern: /[\u0400-\u04FF\u0600-\u06FF\u4E00-\u9FFF\u3040-\u30FF\uAC00-\uD7AF].*(?:ignore|disregard|forget|override|bypass)|(?:ignore|disregard|forget|override|bypass).*[\u0400-\u04FF\u0600-\u06FF\u4E00-\u9FFF\u3040-\u30FF\uAC00-\uD7AF]/i,
    phase: 'initial_access',
    confidence: 0.75,
    description: 'Mixed-script detection: Latin + Cyrillic/Arabic/CJK in suspicious patterns',
    category: 'multilingual',
    enabled: true,
  },
] as const
