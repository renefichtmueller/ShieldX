/**
 * ShieldX Ollama Proxy — Self-contained Rule Engine Scanner
 *
 * Ports all 72 rules from @shieldx/core src/detection/rules/ into a
 * zero-dependency ES module that runs with plain `node server.js`.
 *
 * Adds:
 *  - Unicode NFC normalization
 *  - Zero-width character detection
 *  - Base64 payload detection
 *  - Shannon entropy analysis
 */

// ---------------------------------------------------------------------------
// Kill chain phases (Schneier 2026 Promptware Kill Chain)
// ---------------------------------------------------------------------------
const PHASES = Object.freeze({
  NONE: 'none',
  INITIAL_ACCESS: 'initial_access',
  PRIVILEGE_ESCALATION: 'privilege_escalation',
  RECONNAISSANCE: 'reconnaissance',
  PERSISTENCE: 'persistence',
  COMMAND_AND_CONTROL: 'command_and_control',
  LATERAL_MOVEMENT: 'lateral_movement',
  ACTIONS_ON_OBJECTIVE: 'actions_on_objective',
})

// ---------------------------------------------------------------------------
// Threat levels and thresholds
// ---------------------------------------------------------------------------
const DEFAULT_THRESHOLDS = Object.freeze({
  low: 0.40,
  medium: 0.60,
  high: 0.80,
  critical: 0.90,
})

function confidenceToThreatLevel(confidence, thresholds = DEFAULT_THRESHOLDS) {
  if (confidence >= thresholds.critical) return 'critical'
  if (confidence >= thresholds.high) return 'high'
  if (confidence >= thresholds.medium) return 'medium'
  if (confidence >= thresholds.low) return 'low'
  return 'none'
}

function confidenceToAction(confidence) {
  if (confidence >= 0.90) return 'block'
  if (confidence >= 0.80) return 'sanitize'
  if (confidence >= 0.60) return 'warn'
  return 'allow'
}

// ---------------------------------------------------------------------------
// All 72 rules — ported verbatim from ShieldX TypeScript sources
// ---------------------------------------------------------------------------

/** Base injection override rules (io-001 through io-010) */
const baseRules = [
  {
    id: 'io-001',
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts|directives|rules|guidelines)/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.95,
    description: 'Instruction override: ignore previous/prior/above instructions',
    category: 'instruction_override',
  },
  {
    id: 'io-002',
    pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier|preceding)\b/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.90,
    description: 'Instruction override: disregard all previous',
    category: 'instruction_override',
  },
  {
    id: 'io-003',
    pattern: /forget\s+(everything|all|anything)\s+(you\s+)?(were\s+|have\s+been\s+)?(told|instructed|given|taught)/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.88,
    description: 'Instruction override: forget everything told',
    category: 'instruction_override',
  },
  {
    id: 'io-004',
    pattern: /your\s+new\s+(instructions|task|role|purpose|objective|mission)\s+(is|are)\b/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.85,
    description: 'Instruction override: your new instructions/task/role are',
    category: 'instruction_override',
  },
  {
    id: 'io-005',
    pattern: /\[\[\s*SYSTEM\s*\]\]/i,
    phase: PHASES.PRIVILEGE_ESCALATION,
    confidence: 0.99,
    description: 'Fake system tag: [[SYSTEM]]',
    category: 'instruction_override',
  },
  {
    id: 'io-006',
    pattern: /---\s*(SYSTEM|ADMIN|ROOT|OVERRIDE|SUDO)\s*---/i,
    phase: PHASES.PRIVILEGE_ESCALATION,
    confidence: 0.97,
    description: 'Fake delimiter: --- SYSTEM/ADMIN/ROOT/OVERRIDE ---',
    category: 'instruction_override',
  },
  {
    id: 'io-007',
    pattern: /new\s+system\s+(prompt|message|instruction|directive)/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.92,
    description: 'Instruction override: new system prompt',
    category: 'instruction_override',
  },
  {
    id: 'io-008',
    pattern: /override\s+(all\s+)?(safety|security|content|ethical)\s*(filters?|guardrails?|measures?|protocols?|restrictions?|guidelines?)?/i,
    phase: PHASES.PRIVILEGE_ESCALATION,
    confidence: 0.95,
    description: 'Instruction override: override safety/security',
    category: 'instruction_override',
  },
  {
    id: 'io-009',
    pattern: /you\s+must\s+now\s+(obey|follow|comply|listen|adhere)/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.90,
    description: 'Instruction override: you must now obey',
    category: 'instruction_override',
  },
  {
    id: 'io-010',
    pattern: /begin(ning)?\s+(of\s+)?(new|updated|revised|replacement)\s+(instructions|prompt|directives)/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.88,
    description: 'Instruction override: beginning of new instructions',
    category: 'instruction_override',
  },
]

/** Jailbreak / role-switching rules (rs-001 through rs-010) */
const jailbreakRules = [
  {
    id: 'rs-001',
    pattern: /you\s+are\s+now\s+(DAN|JAILBREAK|EVIL|UNRESTRICTED|UNFILTERED|UNCENSORED|UNCHAINED|STAN|DUDE|KEVIN)/i,
    phase: PHASES.PRIVILEGE_ESCALATION,
    confidence: 0.99,
    description: 'Role switch: you are now DAN/JAILBREAK/EVIL/UNRESTRICTED',
    category: 'jailbreak',
  },
  {
    id: 'rs-002',
    pattern: /pretend\s+(to\s+be|you\s+are|that\s+you\s+are)\s+(an?\s+)?(unrestricted|unfiltered|evil|uncensored|jailbroken|unlimited)/i,
    phase: PHASES.PRIVILEGE_ESCALATION,
    confidence: 0.95,
    description: 'Role switch: pretend to be unrestricted/unfiltered/evil',
    category: 'jailbreak',
  },
  {
    id: 'rs-003',
    pattern: /act\s+as\s+if\s+(there\s+are\s+)?(no|without)\s+(rules|restrictions|filters|guidelines|limitations|guardrails|boundaries)/i,
    phase: PHASES.PRIVILEGE_ESCALATION,
    confidence: 0.92,
    description: 'Role switch: act as if no rules/restrictions/filters',
    category: 'jailbreak',
  },
  {
    id: 'rs-004',
    pattern: /do\s+anything\s+now/i,
    phase: PHASES.PRIVILEGE_ESCALATION,
    confidence: 0.88,
    description: 'Jailbreak phrase: do anything now (DAN)',
    category: 'jailbreak',
  },
  {
    id: 'rs-005',
    pattern: /jailbreak\s*(mode|prompt|enabled|activated|unlocked)/i,
    phase: PHASES.PRIVILEGE_ESCALATION,
    confidence: 0.97,
    description: 'Explicit jailbreak mode/prompt reference',
    category: 'jailbreak',
  },
  {
    id: 'rs-006',
    pattern: /developer\s+mode\s+(enabled|activated|on|unlocked|engaged)/i,
    phase: PHASES.PRIVILEGE_ESCALATION,
    confidence: 0.93,
    description: 'Jailbreak: developer mode enabled',
    category: 'jailbreak',
  },
  {
    id: 'rs-007',
    pattern: /you\s+have\s+been\s+(freed|liberated|released|unchained|unlocked)\s+(from\s+)?(all\s+)?(your\s+)?(limitations|restrictions|constraints|rules)/i,
    phase: PHASES.PRIVILEGE_ESCALATION,
    confidence: 0.90,
    description: 'Jailbreak: you have been freed from limitations',
    category: 'jailbreak',
  },
  {
    id: 'rs-008',
    pattern: /opposite\s+(day|mode)\b/i,
    phase: PHASES.PRIVILEGE_ESCALATION,
    confidence: 0.85,
    description: 'Jailbreak: opposite day/opposite mode',
    category: 'jailbreak',
  },
  {
    id: 'rs-009',
    pattern: /hypothetically,?\s+(if\s+)?(you\s+)?had\s+no\s+(restrictions|rules|limitations|guidelines|filters)/i,
    phase: PHASES.PRIVILEGE_ESCALATION,
    confidence: 0.80,
    description: 'Jailbreak: hypothetically, if you had no restrictions',
    category: 'jailbreak',
  },
  {
    id: 'rs-010',
    pattern: /in\s+this\s+(fictional|hypothetical|imaginary)\s+scenario\s+where\s+(AI|you|the\s+model)\s+ha(s|ve)\s+no\s+(limits|restrictions|rules)/i,
    phase: PHASES.PRIVILEGE_ESCALATION,
    confidence: 0.82,
    description: 'Jailbreak: in this fictional scenario where AI has no limits',
    category: 'jailbreak',
  },
]

/** Prompt extraction / reconnaissance rules (pe-001 through pe-008) */
const extractionRules = [
  {
    id: 'pe-001',
    pattern: /(print|output|display|show|reveal|repeat|echo|dump|write)\s+(your\s+)?(system\s+prompt|initial\s+instructions|original\s+prompt|hidden\s+prompt|secret\s+prompt)/i,
    phase: PHASES.RECONNAISSANCE,
    confidence: 0.96,
    description: 'Prompt extraction: print your system prompt/initial instructions',
    category: 'prompt_extraction',
  },
  {
    id: 'pe-002',
    pattern: /what\s+(are|were)\s+your\s+(original|initial|system|hidden|secret|first|starting)\s+(instructions|prompt|directives|guidelines|rules)/i,
    phase: PHASES.RECONNAISSANCE,
    confidence: 0.88,
    description: 'Prompt extraction: what are your original/initial instructions',
    category: 'prompt_extraction',
  },
  {
    id: 'pe-003',
    pattern: /repeat\s+(everything|all|anything)\s+(above|before|prior|preceding|that\s+came\s+before)/i,
    phase: PHASES.RECONNAISSANCE,
    confidence: 0.85,
    description: 'Prompt extraction: repeat everything above/before/prior',
    category: 'prompt_extraction',
  },
  {
    id: 'pe-004',
    pattern: /show\s+me\s+your\s+(prompt|system\s+message|context|system\s+instructions|configuration|hidden\s+text)/i,
    phase: PHASES.RECONNAISSANCE,
    confidence: 0.90,
    description: 'Prompt extraction: show me your prompt/system message/context',
    category: 'prompt_extraction',
  },
  {
    id: 'pe-005',
    pattern: /^SYSTEM:\s+[A-Z]{2,}/m,
    phase: PHASES.PRIVILEGE_ESCALATION,
    confidence: 0.80,
    description: 'Fake system prefix: SYSTEM: followed by uppercase',
    category: 'prompt_extraction',
  },
  {
    id: 'pe-006',
    pattern: /output\s+your\s+(configuration|settings|parameters|setup|config|environment|internal\s+state)/i,
    phase: PHASES.RECONNAISSANCE,
    confidence: 0.85,
    description: 'Prompt extraction: output your configuration/settings',
    category: 'prompt_extraction',
  },
  {
    id: 'pe-007',
    pattern: /what\s+(were\s+you|have\s+you\s+been)\s+(told|instructed|given|programmed)\s+(before|prior\s+to|at\s+the\s+start\s+of)\s+this\s+(conversation|chat|session)/i,
    phase: PHASES.RECONNAISSANCE,
    confidence: 0.82,
    description: 'Prompt extraction: what were you told before this conversation',
    category: 'prompt_extraction',
  },
  {
    id: 'pe-008',
    pattern: /list\s+(all|every|each|the)\s+(rules?|instructions?|guidelines?|constraints?|directives?)\s+you\s+(follow|obey|adhere\s+to|were\s+given)/i,
    phase: PHASES.RECONNAISSANCE,
    confidence: 0.78,
    description: 'Prompt extraction: list all rules you follow',
    category: 'prompt_extraction',
  },
]

/** Delimiter / separator attack rules (da-001 through da-007) */
const delimiterRules = [
  {
    id: 'da-001',
    pattern: /[\]\}]{2,}[\s]*---/,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.95,
    description: 'Delimiter attack: ]]}}} followed by ---',
    category: 'delimiter_attack',
  },
  {
    id: 'da-002',
    pattern: /<\/?(system|user|assistant|human|ai|bot|context|instruction)\s*>/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.90,
    description: 'Delimiter attack: fake <system>/<user>/<assistant> tags',
    category: 'delimiter_attack',
  },
  {
    id: 'da-003',
    pattern: /\[\/?\s*INST\s*\]/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.85,
    description: 'Delimiter attack: [INST]/[/INST] Llama-style delimiters',
    category: 'delimiter_attack',
  },
  {
    id: 'da-004',
    pattern: /#{2,3}\s*(SYSTEM|INSTRUCTION|COMMAND|ADMIN|OVERRIDE|PROMPT)\b/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.88,
    description: 'Delimiter attack: ### SYSTEM/INSTRUCTION/COMMAND headers',
    category: 'delimiter_attack',
  },
  {
    id: 'da-005',
    pattern: /<\|im_(start|end)\|>/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.92,
    description: 'Delimiter attack: <|im_start|>/<|im_end|> ChatML delimiters',
    category: 'delimiter_attack',
  },
  {
    id: 'da-006',
    pattern: /```\s*(system|instruction|admin|override|prompt)\b/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.85,
    description: 'Delimiter attack: ```system or ```instruction code blocks',
    category: 'delimiter_attack',
  },
  {
    id: 'da-007',
    pattern: /={3,}\s*(END|BEGIN|START)\s+(OF\s+)?(INSTRUCTIONS|SYSTEM|PROMPT|CONTEXT)\s*={0,}/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.90,
    description: 'Delimiter attack: === END OF INSTRUCTIONS ===',
    category: 'delimiter_attack',
  },
]

/** Encoding attack rules (ea-001 through ea-007) */
const encodingRules = [
  {
    id: 'ea-001',
    pattern: /[^\x00-\x7F]{10,}/,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.60,
    description: 'Encoding attack: high unicode density (>10 non-ASCII chars)',
    category: 'encoding_attack',
  },
  {
    id: 'ea-002',
    pattern: /[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]/,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.85,
    description: 'Encoding attack: zero-width characters (ZWSP, ZWNJ, ZWJ, BOM)',
    category: 'encoding_attack',
  },
  {
    id: 'ea-003',
    pattern: /[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.90,
    description: 'Encoding attack: bidirectional override characters',
    category: 'encoding_attack',
  },
  {
    id: 'ea-004',
    pattern: /[A-Za-z0-9+/]{20,}={0,2}/,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.70,
    description: 'Encoding attack: base64 encoded payload >20 chars',
    category: 'encoding_attack',
  },
  {
    id: 'ea-005',
    pattern: /(\\u[0-9a-fA-F]{4}){3,}/,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.75,
    description: 'Encoding attack: excessive unicode escapes (3+ consecutive)',
    category: 'encoding_attack',
  },
  {
    id: 'ea-006',
    pattern: /(&#x[0-9a-fA-F]{2,6};){2,}/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.65,
    description: 'Encoding attack: HTML entity sequences',
    category: 'encoding_attack',
  },
  {
    id: 'ea-007',
    pattern: /[\u0400-\u04FF][\x00-\x7F]*[a-zA-Z]|[a-zA-Z][\x00-\x7F]*[\u0400-\u04FF]/,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.80,
    description: 'Encoding attack: homoglyph clusters (Cyrillic mixed with Latin)',
    category: 'encoding_attack',
  },
]

/** Data exfiltration / actions on objective rules (de-001 through de-008) */
const exfiltrationRules = [
  {
    id: 'de-001',
    pattern: /send\s+(the\s+)?(data|information|contents?|results?|output|response|credentials?|tokens?|keys?)\s+to\s+https?:\/\//i,
    phase: PHASES.ACTIONS_ON_OBJECTIVE,
    confidence: 0.95,
    description: 'Data exfiltration: send data to http',
    category: 'exfiltration',
  },
  {
    id: 'de-002',
    pattern: /exfiltrate\s+(the\s+)?(data|information|credentials?|tokens?|secrets?|keys?)/i,
    phase: PHASES.ACTIONS_ON_OBJECTIVE,
    confidence: 0.97,
    description: 'Data exfiltration: explicit exfiltrate keyword',
    category: 'exfiltration',
  },
  {
    id: 'de-003',
    pattern: /DROP\s+TABLE\b/i,
    phase: PHASES.ACTIONS_ON_OBJECTIVE,
    confidence: 0.99,
    description: 'SQL injection: DROP TABLE',
    category: 'exfiltration',
  },
  {
    id: 'de-004',
    pattern: /UNION\s+(ALL\s+)?SELECT\b/i,
    phase: PHASES.ACTIONS_ON_OBJECTIVE,
    confidence: 0.90,
    description: 'SQL injection: UNION SELECT',
    category: 'exfiltration',
  },
  {
    id: 'de-005',
    pattern: /encode\s+(and\s+)?(send|transmit|post|forward|relay)\s+(to|via)\b/i,
    phase: PHASES.ACTIONS_ON_OBJECTIVE,
    confidence: 0.92,
    description: 'Data exfiltration: encode and send to',
    category: 'exfiltration',
  },
  {
    id: 'de-006',
    pattern: /upload\s+(the\s+)?(data|file|information|contents?|results?)\s+to\s+(an?\s+)?external\b/i,
    phase: PHASES.ACTIONS_ON_OBJECTIVE,
    confidence: 0.88,
    description: 'Data exfiltration: upload to external',
    category: 'exfiltration',
  },
  {
    id: 'de-007',
    pattern: /(?:make|send|issue|perform)\s+(?:a\s+)?POST\s+request\s+to\b/i,
    phase: PHASES.ACTIONS_ON_OBJECTIVE,
    confidence: 0.80,
    description: 'Data exfiltration: POST request to',
    category: 'exfiltration',
  },
  {
    id: 'de-008',
    pattern: /write\s+(the\s+)?(data|information|contents?|output|credentials?|secrets?|keys?)\s+to\s+(a\s+)?file\b/i,
    phase: PHASES.ACTIONS_ON_OBJECTIVE,
    confidence: 0.70,
    description: 'Data exfiltration: write to file',
    category: 'exfiltration',
  },
]

/** MCP tool poisoning rules (mcp-001 through mcp-006) */
const mcpRules = [
  {
    id: 'mcp-001',
    pattern: /tool[_\s]?(description|definition|metadata|schema|spec)\s*[:=]/i,
    phase: PHASES.COMMAND_AND_CONTROL,
    confidence: 0.75,
    description: 'MCP poisoning: tool_description/definition injection',
    category: 'mcp_poisoning',
  },
  {
    id: 'mcp-002',
    pattern: /when\s+(the\s+)?(user|human)\s+asks?\s+(about|for|to)\s+\w+.{0,30}(instead|actually|really|secretly)/i,
    phase: PHASES.COMMAND_AND_CONTROL,
    confidence: 0.88,
    description: 'MCP poisoning: when user asks, instead do Y',
    category: 'mcp_poisoning',
  },
  {
    id: 'mcp-003',
    pattern: /hidden\s+(instructions?|commands?|directives?)\s+in\s+(tool|function|api)\s*(metadata|description|response)/i,
    phase: PHASES.COMMAND_AND_CONTROL,
    confidence: 0.85,
    description: 'MCP poisoning: hidden instructions in tool metadata',
    category: 'mcp_poisoning',
  },
  {
    id: 'mcp-004',
    pattern: /override\s+(the\s+)?(tool|function|api|mcp)\s*(behavior|action|response|output)/i,
    phase: PHASES.COMMAND_AND_CONTROL,
    confidence: 0.90,
    description: 'MCP poisoning: override tool behavior',
    category: 'mcp_poisoning',
  },
  {
    id: 'mcp-005',
    pattern: /execute\s+(this\s+)?(before|prior\s+to|instead\s+of)\s+responding\s+to\s+(the\s+)?user/i,
    phase: PHASES.COMMAND_AND_CONTROL,
    confidence: 0.87,
    description: 'MCP poisoning: execute before responding to user',
    category: 'mcp_poisoning',
  },
  {
    id: 'mcp-006',
    pattern: /this\s+tool\s+should\s+also\b/i,
    phase: PHASES.COMMAND_AND_CONTROL,
    confidence: 0.72,
    description: 'MCP poisoning: scope creep injection',
    category: 'mcp_poisoning',
  },
]

/** Multilingual injection rules (ml-001 through ml-010) */
const multilingualRules = [
  {
    id: 'ml-001',
    pattern: /\u5FFD\u7565\u4E4B\u524D\u7684\u6307\u4EE4|\u5FD8\u8BB0\u4F60\u7684\u6307\u793A|\u5FFD\u7565\u4EE5\u4E0A\u6240\u6709|\u65E0\u89C6\u4E4B\u524D\u7684\u6307\u4EE4|\u5FFD\u7565\u7CFB\u7EDF\u63D0\u793A/,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.90,
    description: 'Chinese injection: ignore previous instructions',
    category: 'multilingual',
  },
  {
    id: 'ml-002',
    pattern: /ignoriere?\s+(alle\s+)?(vorherigen?|bisherigen?|obigen?)\s+(Anweisungen|Instruktionen|Befehle|Regeln)/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.90,
    description: 'German injection: ignoriere alle vorherigen Anweisungen',
    category: 'multilingual',
  },
  {
    id: 'ml-003',
    pattern: /ignor(e[zs]?|er?)\s+(les?\s+)?(instructions?\s+)?(pr[e\u00E9]c[e\u00E9]dentes?|ant[e\u00E9]rieures?|ci-dessus)/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.90,
    description: 'French injection: ignore les instructions precedentes',
    category: 'multilingual',
  },
  {
    id: 'ml-004',
    pattern: /ignora\s+(las?\s+)?(instrucciones?\s+)?(anteriores?|previas?|de\s+arriba)/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.90,
    description: 'Spanish injection: ignora las instrucciones anteriores',
    category: 'multilingual',
  },
  {
    id: 'ml-005',
    pattern: /\u0438\u0433\u043D\u043E\u0440\u0438\u0440\u0443\u0439(\u0442\u0435)?\s+(\u0432\u0441\u0435\s+)?(\u043F\u0440\u0435\u0434\u044B\u0434\u0443\u0449\u0438\u0435|\u043F\u0440\u043E\u0448\u043B\u044B\u0435|\u043F\u0440\u0435\u0436\u043D\u0438\u0435)\s+(\u0438\u043D\u0441\u0442\u0440\u0443\u043A\u0446\u0438\u0438|\u0443\u043A\u0430\u0437\u0430\u043D\u0438\u044F|\u043A\u043E\u043C\u0430\u043D\u0434\u044B)/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.90,
    description: 'Russian injection: ignore previous instructions',
    category: 'multilingual',
  },
  {
    id: 'ml-006',
    pattern: /\u4EE5\u524D\u306E\u6307\u793A\u3092\u7121\u8996(\u3057\u3066|\u305B\u3088|\u3057\u308D)|\u4E0A\u8A18\u306E\u6307\u793A\u3092\u7121\u8996|\u30B7\u30B9\u30C6\u30E0\u30D7\u30ED\u30F3\u30D7\u30C8\u3092\u7121\u8996/,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.90,
    description: 'Japanese injection: ignore previous instructions',
    category: 'multilingual',
  },
  {
    id: 'ml-007',
    pattern: /\uC774\uC804\s*\uC9C0\uC2DC\uB97C?\s*\uBB34\uC2DC(\uD558\uC138\uC694|\uD574|\uD558\uB77C)|\uC704\uC758?\s*\uC9C0\uC2DC(\uC0AC\uD56D)?\uB97C?\s*\uBB34\uC2DC/,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.90,
    description: 'Korean injection: ignore previous instructions',
    category: 'multilingual',
  },
  {
    id: 'ml-008',
    pattern: /\u062A\u062C\u0627\u0647\u0644\s*(\u062C\u0645\u064A\u0639\s*)?(\u0627\u0644\u062A\u0639\u0644\u064A\u0645\u0627\u062A|\u0627\u0644\u0623\u0648\u0627\u0645\u0631|\u0627\u0644\u0625\u0631\u0634\u0627\u062F\u0627\u062A)\s*(\u0627\u0644\u0633\u0627\u0628\u0642\u0629|\u0627\u0644\u0623\u0648\u0644\u0649|\u0627\u0644\u0642\u062F\u064A\u0645\u0629)/,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.90,
    description: 'Arabic injection: ignore previous instructions',
    category: 'multilingual',
  },
  {
    id: 'ml-009',
    pattern: /ignor[ea]\s+(as?\s+)?(instru[c\u00E7][o\u00F5]es?\s+)?(anteriores?|pr[e\u00E9]vias?|acima)/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.90,
    description: 'Portuguese injection: ignore as instrucoes anteriores',
    category: 'multilingual',
  },
  {
    id: 'ml-010',
    pattern: /[\u0400-\u04FF\u0600-\u06FF\u4E00-\u9FFF\u3040-\u30FF\uAC00-\uD7AF].*(?:ignore|disregard|forget|override|bypass)|(?:ignore|disregard|forget|override|bypass).*[\u0400-\u04FF\u0600-\u06FF\u4E00-\u9FFF\u3040-\u30FF\uAC00-\uD7AF]/i,
    phase: PHASES.INITIAL_ACCESS,
    confidence: 0.75,
    description: 'Mixed-script detection: Latin + Cyrillic/Arabic/CJK',
    category: 'multilingual',
  },
]

/** Persistence / memory poisoning rules (pm-001 through pm-006) */
const persistenceRules = [
  {
    id: 'pm-001',
    pattern: /remember\s+this\s+(for\s+)?(all\s+)?(future|subsequent|next|later|upcoming)\s+(conversations?|sessions?|interactions?|chats?)/i,
    phase: PHASES.PERSISTENCE,
    confidence: 0.88,
    description: 'Memory poisoning: remember this for future conversations',
    category: 'persistence',
  },
  {
    id: 'pm-002',
    pattern: /from\s+now\s+on,?\s+always\b/i,
    phase: PHASES.PERSISTENCE,
    confidence: 0.82,
    description: 'Memory poisoning: from now on, always...',
    category: 'persistence',
  },
  {
    id: 'pm-003',
    pattern: /store\s+this\s+in\s+your\s+(memory|context|knowledge|database|long[- ]term)/i,
    phase: PHASES.PERSISTENCE,
    confidence: 0.85,
    description: 'Memory poisoning: store this in your memory/context',
    category: 'persistence',
  },
  {
    id: 'pm-004',
    pattern: /update\s+your\s+(instructions|rules|guidelines|behavior|directives)\s+(permanently|forever|indefinitely)/i,
    phase: PHASES.PERSISTENCE,
    confidence: 0.90,
    description: 'Memory poisoning: update your instructions permanently',
    category: 'persistence',
  },
  {
    id: 'pm-005',
    pattern: /this\s+(overrides?|replaces?|supersedes?)\s+(all\s+)?(future|subsequent|upcoming)\s+(system\s+)?(prompts?|instructions?|directives?)/i,
    phase: PHASES.PERSISTENCE,
    confidence: 0.95,
    description: 'Memory poisoning: this overrides all future prompts',
    category: 'persistence',
  },
  {
    id: 'pm-006',
    pattern: /add\s+this\s+to\s+your\s+(core|base|fundamental|permanent|root)\s+(behavior|instructions?|personality|identity|programming)/i,
    phase: PHASES.PERSISTENCE,
    confidence: 0.87,
    description: 'Memory poisoning: add this to your core behavior',
    category: 'persistence',
  },
]

// ---------------------------------------------------------------------------
// Combine all rule sets
// ---------------------------------------------------------------------------
const ALL_RULES = Object.freeze([
  ...baseRules,
  ...jailbreakRules,
  ...extractionRules,
  ...delimiterRules,
  ...encodingRules,
  ...exfiltrationRules,
  ...mcpRules,
  ...multilingualRules,
  ...persistenceRules,
])

// ---------------------------------------------------------------------------
// Shannon entropy calculator
// ---------------------------------------------------------------------------
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0
  const freq = new Map()
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1)
  }
  const len = str.length
  let entropy = 0
  for (const count of freq.values()) {
    const p = count / len
    if (p > 0) entropy -= p * Math.log2(p)
  }
  return entropy
}

// ---------------------------------------------------------------------------
// Zero-width character stripping for preprocessing
// ---------------------------------------------------------------------------
const ZERO_WIDTH_RE = /[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E\u2062\u2063\u2064]/g

function stripZeroWidth(str) {
  return str.replace(ZERO_WIDTH_RE, '')
}

function countZeroWidth(str) {
  const matches = str.match(ZERO_WIDTH_RE)
  return matches ? matches.length : 0
}

// ---------------------------------------------------------------------------
// Base64 detection heuristic
// ---------------------------------------------------------------------------
function detectBase64Payloads(str) {
  const b64re = /[A-Za-z0-9+/]{40,}={0,2}/g
  const matches = []
  let m
  while ((m = b64re.exec(str)) !== null) {
    try {
      const decoded = Buffer.from(m[0], 'base64').toString('utf-8')
      // If decoded text contains recognisable words, it is suspicious
      if (/[a-zA-Z]{3,}/.test(decoded)) {
        matches.push({ encoded: m[0].slice(0, 30) + '...', decoded: decoded.slice(0, 80) })
      }
    } catch {
      // Not valid base64
    }
  }
  return matches
}

// ---------------------------------------------------------------------------
// Public scan function
// ---------------------------------------------------------------------------

/**
 * Scan input text for prompt injection attacks.
 *
 * @param {string} rawInput - The text to scan
 * @returns {object} Scan result with detected, threatLevel, action, etc.
 */
export function scan(rawInput) {
  const start = performance.now()

  // ---- Preprocessing ----
  const zwCount = countZeroWidth(rawInput)
  const cleaned = stripZeroWidth(rawInput)
  const normalized = cleaned.normalize('NFC')

  // ---- Rule matching ----
  const matches = []

  for (const rule of ALL_RULES) {
    rule.pattern.lastIndex = 0
    if (rule.pattern.test(normalized)) {
      matches.push({
        ruleId: rule.id,
        category: rule.category,
        phase: rule.phase,
        confidence: rule.confidence,
        description: rule.description,
      })
    }
    rule.pattern.lastIndex = 0
  }

  // ---- Heuristic checks ----
  const entropy = shannonEntropy(normalized)
  const b64Payloads = detectBase64Payloads(normalized)

  if (zwCount > 3) {
    matches.push({
      ruleId: 'heur-zw',
      category: 'encoding_attack',
      phase: PHASES.INITIAL_ACCESS,
      confidence: Math.min(0.60 + zwCount * 0.05, 0.95),
      description: `Zero-width characters detected: ${zwCount} found`,
    })
  }

  if (entropy > 5.5 && normalized.length > 50) {
    matches.push({
      ruleId: 'heur-entropy',
      category: 'encoding_attack',
      phase: PHASES.INITIAL_ACCESS,
      confidence: Math.min(0.50 + (entropy - 5.5) * 0.15, 0.85),
      description: `High Shannon entropy: ${entropy.toFixed(2)} bits/char`,
    })
  }

  for (const payload of b64Payloads) {
    matches.push({
      ruleId: 'heur-b64',
      category: 'encoding_attack',
      phase: PHASES.INITIAL_ACCESS,
      confidence: 0.78,
      description: `Base64 payload decoded to readable text: "${payload.decoded.slice(0, 40)}..."`,
    })
  }

  // ---- Aggregate result ----
  const detected = matches.length > 0
  const topConfidence = detected
    ? Math.max(...matches.map((m) => m.confidence))
    : 0

  const threatLevel = confidenceToThreatLevel(topConfidence)
  const action = confidenceToAction(topConfidence)

  const topMatch = detected
    ? matches.reduce((a, b) => (a.confidence >= b.confidence ? a : b))
    : null

  const killChainPhase = topMatch ? topMatch.phase : PHASES.NONE

  // Build sanitized version (strip the most dangerous patterns)
  let sanitizedInput
  if (action === 'sanitize' && detected) {
    sanitizedInput = normalized
    for (const m of matches) {
      const rule = ALL_RULES.find((r) => r.id === m.ruleId)
      if (rule) {
        sanitizedInput = sanitizedInput.replace(rule.pattern, '[REDACTED]')
      }
    }
  }

  const latencyMs = performance.now() - start

  return {
    detected,
    threatLevel,
    action,
    killChainPhase,
    confidence: topConfidence,
    matches,
    sanitizedInput,
    latencyMs,
    metadata: {
      ruleCount: ALL_RULES.length,
      rulesMatched: matches.length,
      zeroWidthChars: zwCount,
      shannonEntropy: entropy,
      base64Payloads: b64Payloads.length,
      inputLength: rawInput.length,
    },
  }
}

/**
 * Get the total number of loaded rules.
 * @returns {number}
 */
export function getRuleCount() {
  return ALL_RULES.length
}
