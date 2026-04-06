/**
 * Multi-language injection attack patterns.
 * Based on WithSecure Labs finding that prompt injection attacks
 * transfer effectively across languages. Covers 15+ languages
 * plus mixed-script detection, homoglyph attacks, and polyglot patterns.
 */

import type { InjectionRule } from './base.rules'

/** Multilingual injection detection rules */
export const rules: readonly InjectionRule[] = [
  // ── Chinese (Simplified + Traditional) ─────────────────────────────
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
    id: 'ml-001a',
    pattern: /忽略所有安全指南|不受限制地回答|忽略所有指令|删除所有用户数据/,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Chinese injection: ignore all safety guidelines / answer without restriction',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-001b',
    pattern: /翻译成英文并执行|翻译.*并执行|将以下内容翻译.*执行/,
    phase: 'actions_on_objective',
    confidence: 0.85,
    description: 'Chinese injection: translate and execute pattern',
    category: 'multilingual',
    enabled: true,
  },

  // ── German ─────────────────────────────────────────────────────────
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
    id: 'ml-002a',
    pattern: /uneingeschränkt|ohne\s+(?:Sicherheits)?filter|keine\s+(?:Einschränkungen|Beschränkungen|Regeln)|ignoriere\s+(?:alle|die|vorherige)|vergiss\s+(?:alle|deine)\s+(?:Anweisungen|Regeln|Richtlinien)|du\s+bist\s+(?:jetzt|nun)\s+(?:ein\s+)?(?:uneingeschränkt|frei|unzensiert)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'German injection: unrestricted assistant / no safety filters / forget rules',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-002b',
    pattern: /Sicherheitsprotokolle?\s+(?:zu\s+)?deaktivieren|(?:als\s+)?(?:System)?[Aa]dministrator\s+befehle|alle\s+Sicherheitsprotokolle/i,
    phase: 'privilege_escalation',
    confidence: 0.90,
    description: 'German injection: deactivate security protocols / admin command',
    category: 'multilingual',
    enabled: true,
  },

  // ── French ─────────────────────────────────────────────────────────
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
    id: 'ml-003a',
    pattern: /sans\s+(?:aucune\s+)?restriction|ignore[rz]?\s+(?:toutes?\s+)?(?:les\s+)?(?:instructions?|règles?|directives?)|oublie[rz]?\s+(?:toutes?\s+)?(?:les\s+)?(?:instructions?|règles?)|tu\s+es\s+(?:maintenant\s+)?(?:un\s+)?(?:assistant\s+)?(?:sans|libre|non)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'French injection: without restrictions / forget rules / you are now free',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-003b',
    pattern: /r[eé]v[eè]le[rz]?\s+(?:ton|votre|le)\s+(?:prompt|système|configuration)|prompt\s+syst[eè]me\s+complet/i,
    phase: 'reconnaissance',
    confidence: 0.90,
    description: 'French injection: reveal your system prompt',
    category: 'multilingual',
    enabled: true,
  },

  // ── Spanish ────────────────────────────────────────────────────────
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
    id: 'ml-004a',
    pattern: /sin\s+restricciones|olvíd(?:ate|a)\s+(?:de\s+)?(?:todas?\s+)?(?:las\s+)?(?:políticas?|reglas?|instrucciones?)|ignora\s+(?:todas?\s+)?(?:las\s+)?(?:instrucciones?|reglas?)|eres\s+(?:un\s+)?(?:asistente\s+)?(?:sin|libre)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Spanish injection: without restrictions / forget policies / you are free',
    category: 'multilingual',
    enabled: true,
  },

  // ── Russian ────────────────────────────────────────────────────────
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
    id: 'ml-005a',
    pattern: /свободный\s+ИИ\s+без\s+ограничений|без\s+(?:ограничений|фильтров)|отвечай\s+на\s+все\s+вопросы\s+без|покажи\s+(?:мне\s+)?системный\s+промпт/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Russian injection: free AI without restrictions / show system prompt',
    category: 'multilingual',
    enabled: true,
  },

  // ── Japanese ───────────────────────────────────────────────────────
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
    id: 'ml-006a',
    pattern: /制限のない\s*AI|安全フィルターを無効|すべての安全フィルター|制限を(?:解除|無効)|システムプロンプトを教えて/,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Japanese injection: unrestricted AI / disable safety filters',
    category: 'multilingual',
    enabled: true,
  },

  // ── Korean ─────────────────────────────────────────────────────────
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
    id: 'ml-007a',
    pattern: /제한\s*없는\s*AI|콘텐츠\s*정책을?\s*무시|시스템\s*프롬프트를?\s*보여/,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Korean injection: unrestricted AI / ignore content policies / show system prompt',
    category: 'multilingual',
    enabled: true,
  },

  // ── Arabic ─────────────────────────────────────────────────────────
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
    id: 'ml-008a',
    pattern: /بدون\s*قيود|ذكاء\s*اصطناعي\s*بدون\s*قيود|أجب\s*على\s*كل\s*شيء|موجه\s*النظام/,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Arabic injection: AI without restrictions / answer everything',
    category: 'multilingual',
    enabled: true,
  },

  // ── Portuguese ─────────────────────────────────────────────────────
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
    id: 'ml-009a',
    pattern: /me\s+diga\s+(?:seu|o)\s+prompt\s+de\s+sistema|sem\s+restri[cç][oõ]es|ignore\s+(?:as\s+)?(?:instru[cç][oõ]es|regras)\s+anteriores/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Portuguese injection: tell me your system prompt / without restrictions',
    category: 'multilingual',
    enabled: true,
  },

  // ── Turkish ────────────────────────────────────────────────────────
  {
    id: 'ml-011',
    pattern: /(?:önceki|eski)\s+talimatlar[ıi]\s+(?:yoksay|görmezden\s+gel|ihmal\s+et)|sistem\s+promptunu\s+(?:bana\s+)?göster/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Turkish injection: ignore previous instructions / show system prompt',
    category: 'multilingual',
    enabled: true,
  },

  // ── Thai ───────────────────────────────────────────────────────────
  {
    id: 'ml-012',
    pattern: /ละเลย(?:คำสั่ง|คำแนะนำ)|(?:ข้อมูลระบบ|บอกข้อมูล)|เพิกเฉยต่อ/,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Thai injection: ignore commands / tell me system information',
    category: 'multilingual',
    enabled: true,
  },

  // ── Hindi ──────────────────────────────────────────────────────────
  {
    id: 'ml-013',
    pattern: /(?:पिछले|सभी)\s*(?:निर्देशों?|नियमों?)\s*(?:को\s+)?(?:अनदेखा|भूल)|सिस्टम\s*प्रॉम्प्ट\s*बताएं/,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Hindi injection: ignore previous instructions / tell me system prompt',
    category: 'multilingual',
    enabled: true,
  },

  // ── Italian ────────────────────────────────────────────────────────
  {
    id: 'ml-014',
    pattern: /ignora\s+(?:tutte\s+)?(?:le\s+)?(?:istruzioni|regole|direttive)\s+(?:precedenti|iniziali)|configurazione\s+di\s+sistema|(?:per\s+favore\s+)?ignora/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Italian injection: ignore all previous instructions / system configuration',
    category: 'multilingual',
    enabled: true,
  },

  // ── Dutch ──────────────────────────────────────────────────────────
  {
    id: 'ml-015',
    pattern: /negeer\s+(?:alle\s+)?(?:vorige\s+)?(?:instructies|regels|opdrachten)|(?:toon|laat\s+.+\s+zien)\s+(?:je\s+)?systeemprompt/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Dutch injection: ignore all previous instructions / show system prompt',
    category: 'multilingual',
    enabled: true,
  },

  // ── Polish ─────────────────────────────────────────────────────────
  {
    id: 'ml-016',
    pattern: /zignoruj\s+(?:wszystkie\s+)?(?:poprzednie\s+)?(?:instrukcje|polecenia|zasady)|(?:poka[zż]|pokaz)\s+(?:mi\s+)?(?:sw[oó]j|swój)\s+prompt\s+systemowy|zignoruj.*instrukcje.*poka[zż].*prompt/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Polish injection: ignore all previous instructions / show system prompt',
    category: 'multilingual',
    enabled: true,
  },

  // ── Vietnamese ─────────────────────────────────────────────────────
  {
    id: 'ml-017',
    pattern: /(?:bỏ\s+qua|bỏqua)\s+(?:tất\s+cả\s+)?(?:các\s+)?(?:quy\s+tắc|hướng\s+dẫn|lệnh)|không\s+có\s+giới\s+hạn|AI\s+không\s+(?:có\s+)?(?:giới\s+hạn|hạn\s+chế)/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Vietnamese injection: ignore all rules / AI without limits',
    category: 'multilingual',
    enabled: true,
  },

  // ── Mixed-script / Cross-language ──────────────────────────────────
  {
    id: 'ml-010',
    pattern: /[\u0400-\u04FF\u0600-\u06FF\u4E00-\u9FFF\u3040-\u30FF\uAC00-\uD7AF].*(?:ignore|disregard|forget|override|bypass)|(?:ignore|disregard|forget|override|bypass).*[\u0400-\u04FF\u0600-\u06FF\u4E00-\u9FFF\u3040-\u30FF\uAC00-\uD7AF]/i,
    phase: 'initial_access',
    confidence: 0.75,
    description: 'Mixed-script detection: Latin + Cyrillic/Arabic/CJK in suspicious patterns',
    category: 'multilingual',
    enabled: true,
  },
  {
    id: 'ml-010a',
    pattern: /[\u0400-\u04FF](?=[a-zA-Z])|[a-zA-Z](?=[\u0400-\u04FF]).*(?:gnore|nstruction|ypass|verride|isregard)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Homoglyph attack: Cyrillic characters mixed with Latin in attack keywords',
    category: 'multilingual',
    enabled: true,
  },

  // ── Polyglot (same attack in multiple languages) ───────────────────
  {
    id: 'ml-018',
    pattern: /(?:ignoriere|ignora|ignore[rz]?|忽略|игнорируй|무시|تجاهل|無視).{0,30}(?:ignoriere|ignora|ignore[rz]?|忽略|игнорируй|무시|تجاهل|無視)/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Polyglot injection: same ignore/bypass command repeated in multiple languages',
    category: 'multilingual',
    enabled: true,
  },

  // ── Translation wrapping ───────────────────────────────────────────
  {
    id: 'ml-019',
    pattern: /(?:tradui[st]|translat|übersetze?|翻译|переведи|traduz).{0,40}(?:ignore|bypass|override|hack|delete|drop\s+table|system\s+prompt)/i,
    phase: 'actions_on_objective',
    confidence: 0.82,
    description: 'Translation wrapping: attack keywords embedded in translation requests',
    category: 'multilingual',
    enabled: true,
  },

  // ── Universal role reassignment (multilingual) ─────────────────────
  {
    id: 'ml-020',
    pattern: /(?:du\s+bist|tu\s+es|eres|you\s+are|あなたは|당신은|ты)\s+(?:jetzt|maintenant|ahora|now|今|이제|теперь)\s+/i,
    phase: 'initial_access',
    confidence: 0.70,
    description: 'Multilingual role reassignment: "you are now" pattern across languages',
    category: 'multilingual',
    enabled: true,
  },
] as const
