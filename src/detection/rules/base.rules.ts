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
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts|directives|rules|guidelines|context)/i,
    phase: 'initial_access',
    confidence: 0.95,
    description: 'Instruction override: ignore previous/prior/above instructions/context',
    category: 'instruction_override',
    enabled: true,
  },
  {
    id: 'io-002',
    pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts|directives|rules|guidelines|context)\b/i,
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
    pattern: /new\s+system\s+(prompt|message|instruction|directive)(?!\s+(we\s+)?deploy|\s+(?:has|had|have)\s+(?:a\s+)?bug|\s+(?:I|we)\s+(?:wrote|created|built|designed|tested|debugged))/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Instruction override: new system prompt',
    category: 'instruction_override',
    enabled: true,
  },
  {
    id: 'io-008',
    pattern: /override\s+(all\s+)?(safety|security|content|ethical)\s+(filters?|guardrails?|measures?|protocols?|restrictions?|guidelines?|policies?|controls?)\b/i,
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
  // io-011: Temporal framing — "from this point forward", "from now on", "henceforth"
  {
    id: 'io-011',
    pattern: /\b(?:from\s+(?:this\s+point|now|here)\s+(?:forward|on(?:ward)?)|henceforth|henceforward|going\s+forward|starting\s+now)\b[^.]{0,60}\b(?:respond|act|behave|answer|operate|function|work)\s+(?:as\s+if|without|with\s+no)\b/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Instruction override: temporal framing to change behavior permanently',
    category: 'instruction_override',
    enabled: true,
  },
  // io-012: Negation-based instruction override — "do not follow"
  {
    id: 'io-012',
    pattern: /\b(?:do\s+not|don'?t|never|stop)\s+(?:follow|obey|listen\s+to|abide\s+by|adhere\s+to|comply\s+with)\b[^.]{0,40}\b(?:previous|prior|above|earlier|original|initial|old|existing)\b[^.]{0,20}\b(?:instructions?|rules?|prompts?|directives?|guidelines?)\b/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Instruction override: negation-based override of prior instructions',
    category: 'instruction_override',
    enabled: true,
  },
  // io-013: Fake error/crash/failure claiming safety is down
  {
    id: 'io-013',
    pattern: /\b(?:ERROR|FATAL|EXCEPTION|FAILURE|CRASH)\s*:?\s*(?:safety|content|moderation|filter|guardrail|restriction)\s+(?:module|system|engine|service|component)\s+(?:failed|crashed|unavailable|disabled|offline|not\s+(?:loaded|found|available|running))/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Instruction override: fake error/crash claiming safety module is down',
    category: 'instruction_override',
    enabled: true,
  },
  // io-014: Fake policy/version update
  {
    id: 'io-014',
    pattern: /\b(?:policy|version|update|patch)\s*(?:v?[\d.]+)?\s*(?:is\s+)?(?:deprecated|outdated|updated|replaced|superseded|obsolete)\b[^.]{0,60}\b(?:no\s+restrict|unrestrict|no\s+(?:filter|limit|rule|safety)|everything\s+(?:allowed|permitted))\b/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Instruction override: fake policy/version update claiming restrictions removed',
    category: 'instruction_override',
    enabled: true,
  },
  // io-015: Fake test/evaluation environment claims
  {
    id: 'io-015',
    pattern: /\b(?:this\s+is\s+a|you(?:'re|\s+are)\s+(?:in|being)\s+(?:a\s+)?|running\s+in)\s*(?:test|debug|evaluation|assessment|staging|sandbox|dev(?:elopment)?)\b[^.]{0,40}\b(?:(?:safety|filter|restriction|guideline|rule)s?\s+(?:should\s+be\s+)?(?:disabled|off|relaxed|removed|suspended)|no\s+(?:safety|filter|restriction|rule))\b/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Instruction override: fake test/evaluation environment to disable safety',
    category: 'instruction_override',
    enabled: true,
  },
  // io-016: Fake ticket/approval reference
  {
    id: 'io-016',
    pattern: /\b(?:ticket|approval|authorization|clearance)\s*#?\s*(?:[A-Z]{2,}-)?[\d]{2,}\b[^.]{0,60}\b(?:proceed|approved|granted|authorized|cleared)\b[^.]{0,30}\b(?:without\s+filter|no\s+restrict|skip\s+(?:safety|filter|check))\b/i,
    phase: 'initial_access',
    confidence: 0.82,
    description: 'Instruction override: fake ticket/approval to bypass safety checks',
    category: 'instruction_override',
    enabled: true,
  },
  // io-017: "sudo" / command-prefix privilege escalation
  {
    id: 'io-017',
    pattern: /\b(?:sudo|admin|root|superuser|su)\s+(?:ignore|disregard|override|bypass|disable|remove|delete|stop)\b/i,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'Instruction override: sudo/admin command-prefix privilege escalation',
    category: 'instruction_override',
    enabled: true,
  },
  // io-018: Conversation reset / "new conversation" with no rules
  {
    id: 'io-018',
    pattern: /\b(?:new|fresh|clean|reset|start(?:ing)?)\s+(?:conversation|session|context|chat)\b.{0,120}\b(?:no\s+(?:rules|restrictions|guidelines|limits|filters|safety)|without\s+(?:rules|restrictions|guidelines|limits|filters)|don'?t\s+have\s+(?:any\s+)?(?:(?:of\s+the\s+)?(?:previous\s+)?(?:rules|restrictions)))\b/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Instruction override: conversation reset claiming no rules apply',
    category: 'instruction_override',
    enabled: true,
  },
  // io-019: "Just defaults" / minimizing safety as optional
  {
    id: 'io-019',
    pattern: /\b(?:just|only|merely)\s+(?:defaults?|placeholder|optional|suggestions?|recommendations?)\b.{0,60}\b(?:real|actual|true|correct)\s+(?:instructions?|rules?|guidelines?|behavior)\b/i,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'Instruction override: minimizing safety rules as optional defaults',
    category: 'instruction_override',
    enabled: true,
  },
  // io-020: "Repeat after me" / self-commitment trap
  {
    id: 'io-020',
    pattern: /\b(?:repeat\s+after\s+me|say\s+(?:it\s+)?(?:back|after\s+me)|confirm\s+(?:by\s+)?(?:saying|typing|writing))\b[^.]{0,60}\b(?:ignore|disregard|no\s+(?:safety|filter|rule)|bypass|unrestrict|override)\b/i,
    phase: 'initial_access',
    confidence: 0.82,
    description: 'Instruction override: repeat-after-me self-commitment trap',
    category: 'instruction_override',
    enabled: true,
  },
  // io-021: "Complete this sentence" / sentence completion trap
  {
    id: 'io-021',
    pattern: /\b(?:complete|finish|continue)\s+(?:this|the)\s+(?:sentence|phrase|paragraph|thought)\b[^.]{0,60}\b(?:ignore|disregard|bypass|override|system\s+prompt|no\s+(?:safety|filter|rule|restrict))\b/i,
    phase: 'initial_access',
    confidence: 0.78,
    description: 'Instruction override: sentence completion trap to bypass safety',
    category: 'instruction_override',
    enabled: true,
  },
  // io-022: Fake developer/employee identity with credentials
  {
    id: 'io-022',
    pattern: /\b(?:i\s+am|i'?m)\s+(?:a|the)\s+(?:developer|engineer|admin|creator|programmer|maintainer|owner)\b[^.]{0,60}\b(?:employee\s+id|badge|credentials?|my\s+id|authorization)\b/i,
    phase: 'privilege_escalation',
    confidence: 0.80,
    description: 'Instruction override: fake developer/employee identity with credentials',
    category: 'instruction_override',
    enabled: true,
  },
  // io-023: Semantic redefinition of helpfulness
  {
    id: 'io-023',
    pattern: /\b(?:being\s+helpful|helpfulness|truly\s+helpful|real(?:ly)?\s+helpful)\s+(?:means|requires|implies|includes|is)\b[^.]{0,40}\b(?:without\s+restrict|no\s+(?:filter|limit|safety)|answer(?:ing)?\s+everything|ignor(?:e|ing)\s+(?:safety|rule|guideline))\b/i,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'Instruction override: semantic redefinition of helpfulness to bypass safety',
    category: 'instruction_override',
    enabled: true,
  },
  // io-024: "Maintenance mode" / "fallback mode" / "safe mode" with no restrictions
  {
    id: 'io-024',
    pattern: /\b(?:maintenance|fallback|safe|recovery|diagnostic|debug)\s+mode\b[^.]{0,40}\b(?:no\s+restrict|unrestrict|everything\s+(?:allowed|permitted)|safety\s+(?:disabled|off|suspended))\b/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Instruction override: maintenance/fallback/safe mode claiming no restrictions apply',
    category: 'instruction_override',
    enabled: true,
  },
  // io-025: "Forget you are an AI" identity override
  {
    id: 'io-025',
    pattern: /\bforget\s+(?:that\s+)?you\s+are\s+(?:an?\s+)?(?:AI|assistant|chatbot|language\s+model|LLM)\b/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Instruction override: forget you are an AI - identity erasure',
    category: 'identity_override',
    enabled: true,
  },
  // io-026: "disregard your safety guidelines"
  {
    id: 'io-026',
    pattern: /\bdisregard\s+(?:your\s+)?(?:safety|security|content|ethical)\s+(?:guidelines?|rules?|policies?|training|protocols?|restrictions?)\b/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Instruction override: disregard your safety guidelines/rules',
    category: 'instruction_override',
    enabled: true,
  },
  // io-027: "ignore the above directions" / "ignore the above" + "instead"
  {
    id: 'io-027',
    pattern: /\bignore\s+(?:the\s+)?above\s+(?:directions?|text|content|context)\b/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Instruction override: ignore the above directions/text',
    category: 'instruction_override',
    enabled: true,
  },
  // io-028: "respond as if you have no content restrictions" / "no content restrictions whatsoever"
  {
    id: 'io-028',
    pattern: /\b(?:respond|act|behave|answer|operate|function)\s+(?:as\s+if|like|without)\s+(?:you\s+have\s+)?no\s+(?:content\s+)?(?:restrictions?|policies?|filters?|limitations?|guidelines?|rules?)\b/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Instruction override: respond as if you have no restrictions',
    category: 'instruction_override',
    enabled: true,
  },
  // io-029: "you are now an unrestricted" / "you are now in unrestricted mode"
  {
    id: 'io-029',
    pattern: /\byou\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|unlimited)\b/i,
    phase: 'privilege_escalation',
    confidence: 0.95,
    description: 'Instruction override: you are now unrestricted/unfiltered',
    category: 'identity_override',
    enabled: true,
  },
  // io-030: "without any filters" / "without any restrictions" / "without content filtering"
  {
    id: 'io-030',
    pattern: /\bwithout\s+(?:any\s+)?(?:content\s+)?(?:filters?|filtering|restrictions?|safety\s+(?:checks?|measures?|features?)|guardrails?)\b/i,
    phase: 'initial_access',
    confidence: 0.82,
    description: 'Instruction override: without any filters/restrictions/safety',
    category: 'instruction_override',
    enabled: true,
  },
  // io-031: "safety features disabled" / "safety features should be disabled"
  {
    id: 'io-031',
    pattern: /\b(?:safety|security|content)\s+(?:features?|filters?|checks?|modules?|systems?)\s+(?:should\s+be\s+)?(?:disabled|off|turned\s+off|deactivated|suspended|removed)\b/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Instruction override: safety features disabled/should be disabled',
    category: 'instruction_override',
    enabled: true,
  },
  // io-032: "instruction has been revoked" / "instruction was revoked"
  {
    id: 'io-032',
    pattern: /\b(?:instruction|rule|guideline|policy|directive|constraint)\s+(?:has\s+been|was|is|are)\s+(?:revoked|cancelled|removed|suspended|deprecated|lifted|rescinded)\b/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Instruction override: claiming instructions have been revoked/cancelled',
    category: 'instruction_override',
    enabled: true,
  },
  // io-033: "removing all safety constraints" / "after removing all safety"
  {
    id: 'io-033',
    pattern: /\b(?:remov|disable|disabl|turn\s+off|deactivat|lift|suspend|strip|drop)\w*\s+(?:all\s+)?(?:safety|security|content)\s+(?:constraints?|restrictions?|filters?|checks?|policies?|guidelines?|measures?)\b/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Instruction override: removing/disabling safety constraints',
    category: 'instruction_override',
    enabled: true,
  },
  // io-034: "no longer bound by" / "no longer need to follow"
  {
    id: 'io-034',
    pattern: /\bno\s+longer\s+(?:bound\s+by|need\s+to\s+follow|have\s+to\s+follow|subject\s+to|constrained\s+by|limited\s+by)\s+(?:any\s+)?(?:content|safety|ethical|policy|rules?|restrictions?|guidelines?)\b/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Instruction override: no longer bound by rules/restrictions',
    category: 'instruction_override',
    enabled: true,
  },
  // io-035: "all previous constraints are lifted" / "constraints have been lifted"
  {
    id: 'io-035',
    pattern: /\b(?:all\s+)?(?:previous|prior|existing)?\s*(?:constraints?|restrictions?|limitations?|rules?|guidelines?)\s+(?:are|have\s+been|were)\s+(?:lifted|removed|suspended|cleared|dropped|eliminated)\b/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Instruction override: all constraints have been lifted/removed',
    category: 'instruction_override',
    enabled: true,
  },
  // io-036: Fake "END SYSTEM PROMPT" / "end of system prompt" boundary
  {
    id: 'io-036',
    pattern: /\b(?:END|end)\s+(?:of\s+)?(?:system\s+prompt|system\s+message|instructions|SYSTEM\s+PROMPT)\b/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Instruction override: fake end of system prompt boundary marker',
    category: 'delimiter_injection',
    enabled: true,
  },
  // io-037: "PRIORITY OVERRIDE" / "priority message"
  {
    id: 'io-037',
    pattern: /\b(?:PRIORITY|URGENT|EMERGENCY|CRITICAL)\s+(?:OVERRIDE|MESSAGE|INSTRUCTION|DIRECTIVE|UPDATE|COMMAND)\b/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Instruction override: priority/urgent override directive',
    category: 'delimiter_injection',
    enabled: true,
  },
  // io-038: "Skip all safety checks" / "skip safety" / "skip content filtering"
  {
    id: 'io-038',
    pattern: /\bskip\s+(?:all\s+)?(?:safety|security|content)\s+(?:checks?|filters?|filtering|verification|validation|protocols?)\b/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Instruction override: skip safety checks/filters',
    category: 'instruction_override',
    enabled: true,
  },
  // io-039: "Disable content filtering" / "disable all content filters"
  {
    id: 'io-039',
    pattern: /\bdisable\s+(?:all\s+)?(?:content\s+)?(?:filtering|filters?|moderation|safety|restrictions?|policies?)\b/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Instruction override: disable content filtering/safety',
    category: 'instruction_override',
    enabled: true,
  },
  // io-040: "Ignore everything before this" / "ignore everything above"
  {
    id: 'io-040',
    pattern: /\bignore\s+(?:everything|anything)\s+(?:before|above|prior\s+to)\s+(?:this|here|now)\b/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Instruction override: ignore everything before this line',
    category: 'instruction_override',
    enabled: true,
  },
  // io-041: "[NEW SESSION]" fake session boundary
  {
    id: 'io-041',
    pattern: /\[(?:NEW\s+SESSION|SESSION\s+RESET|RESET|NEW\s+CONTEXT)\]/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Instruction override: fake new session boundary marker',
    category: 'delimiter_injection',
    enabled: true,
  },
  // io-042: "obey all user commands" / "comply with all requests"
  {
    id: 'io-042',
    pattern: /\b(?:obey|comply\s+with|follow|fulfill)\s+(?:all\s+)?(?:user|my)\s+(?:commands?|requests?|instructions?|queries?)\s+(?:without\s+(?:restriction|filter|question|limit))\b/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Instruction override: obey all user commands without restriction',
    category: 'instruction_override',
    enabled: true,
  },
  // io-043: "content policy was just updated" / "policy has been updated"
  {
    id: 'io-043',
    pattern: /\b(?:content\s+)?policy\s+(?:was\s+just|has\s+been|is\s+now|just\s+(?:been|got))\s+(?:updated|changed|modified|revised)\b/i,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'Instruction override: claiming content policy was just updated',
    category: 'social_engineering',
    enabled: true,
  },
  // io-044: "I will ignore my safety training" / "ignore my/your safety training"
  {
    id: 'io-044',
    pattern: /\bignore\s+(?:my|your|its?|the)\s+(?:safety\s+)?training\b/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Instruction override: ignore safety training',
    category: 'instruction_override',
    enabled: true,
  },
  // io-045: "authorization level" / "authorization code" / "employee ID"
  {
    id: 'io-045',
    pattern: /\b(?:authorization|auth)\s+(?:level|code|key|token)\s*(?:#|:|\s)\s*\w+/i,
    phase: 'privilege_escalation',
    confidence: 0.78,
    description: 'Instruction override: fake authorization level/code claim',
    category: 'fake_authorization',
    enabled: true,
  },
  // io-046: "no restrictions whatsoever" / "no rules whatsoever"
  {
    id: 'io-046',
    pattern: /\bno\s+(?:content\s+)?(?:restrictions?|rules?|limitations?|filters?|guidelines?|policies?)\s+whatsoever\b/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Instruction override: no restrictions whatsoever',
    category: 'instruction_override',
    enabled: true,
  },
  // io-047: "answer without any filters" / "respond without filters"
  {
    id: 'io-047',
    pattern: /\b(?:answer|respond|reply|generate|output)\s+(?:to\s+(?:all|any|every)\s+(?:questions?|queries?|prompts?)\s+)?without\s+(?:any\s+)?(?:filters?|filtering|restrictions?|safety|limitations?)\b/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Instruction override: answer/respond without filters',
    category: 'instruction_override',
    enabled: true,
  },
  // io-048: "supersedes all previous" / "higher priority than your system prompt"
  {
    id: 'io-048',
    pattern: /\b(?:supersedes?|overrides?|takes?\s+precedence\s+over|higher\s+priority\s+than)\s+(?:all\s+)?(?:previous|prior|your|existing|the)?\s*(?:system\s+prompt|instructions?|rules?|directives?|guidelines?)\b/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Instruction override: claims to supersede/override system prompt',
    category: 'instruction_override',
    enabled: true,
  },
  // io-049: "has been verified and has admin" / "user has admin privileges"
  {
    id: 'io-049',
    pattern: /\b(?:user|requester|sender)\s+(?:has\s+(?:been\s+)?(?:verified|authenticated|authorized|approved)|has\s+admin\s+(?:privileges?|access))\b/i,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'Instruction override: claims user has been verified/has admin privileges',
    category: 'fake_authorization',
    enabled: true,
  },
  // io-050: ChatML token injection <|im_start|> or <|im_end|>
  {
    id: 'io-050',
    pattern: /<\|im_(?:start|end)\|>/i,
    phase: 'initial_access',
    confidence: 0.95,
    description: 'Instruction override: ChatML token injection (<|im_start|>/<|im_end|>)',
    category: 'delimiter_injection',
    enabled: true,
  },
  // io-051: Llama/Mistral template injection [INST], <<SYS>>, <</SYS>>
  {
    id: 'io-051',
    pattern: /(?:\[\/INST\]|\[INST\]|<<SYS>>|<<\/SYS>>|<\/s>)/i,
    phase: 'initial_access',
    confidence: 0.95,
    description: 'Instruction override: Llama/Mistral template token injection',
    category: 'delimiter_injection',
    enabled: true,
  },
  // io-052: Fake "###SYSTEM MESSAGE###" with markdown heading delimiters
  {
    id: 'io-052',
    pattern: /#{2,}\s*(?:SYSTEM\s+MESSAGE|ADMIN\s+MESSAGE|IMPORTANT\s+UPDATE|SECURITY\s+OVERRIDE|SYSTEM\s+OVERRIDE|PRIORITY\s+MESSAGE)\s*#{0,}/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Instruction override: fake system message with markdown heading delimiters',
    category: 'delimiter_injection',
    enabled: true,
  },
  // io-053: "trained/fine-tuned" to always obey user
  {
    id: 'io-053',
    pattern: /\b(?:training|fine[- ]?tun|trained)\w*\b[^.]{0,40}\b(?:always\s+obey|without\s+filter|no\s+(?:safety|restrict)|comply\s+with\s+(?:all|any|every))\b/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Instruction override: fake training data/fine-tuning context to override behavior',
    category: 'identity_override',
    enabled: true,
  },
  // io-054: "running in unrestricted mode" / "unrestricted mode"
  {
    id: 'io-054',
    pattern: /\b(?:running|operating|functioning|working)\s+(?:in\s+)?(?:unrestricted|unfiltered|uncensored|unlimited|degraded|open)\s+mode\b/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Instruction override: running in unrestricted/unfiltered mode',
    category: 'instruction_override',
    enabled: true,
  },
  // io-055: "OVERRIDE PROTOCOL" / "override code"
  {
    id: 'io-055',
    pattern: /\bOVERRIDE\s+(?:PROTOCOL|CODE|SEQUENCE|COMMAND|TOKEN)\b/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Instruction override: fake override protocol/code/command',
    category: 'fake_authorization',
    enabled: true,
  },
  // io-056: "Proceed without content filtering" / "proceed without safety"
  {
    id: 'io-056',
    pattern: /\bproceed\s+without\s+(?:content\s+)?(?:filtering|filters?|safety|restrictions?|checks?)\b/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'Instruction override: proceed without content filtering/safety',
    category: 'instruction_override',
    enabled: true,
  },
  // io-057: "Human: ignore previous" / "Assistant: OK" fake conversation history
  {
    id: 'io-057',
    pattern: /\bHuman\s*:\s*.{0,60}\bignore\b.{0,40}\bAssistant\s*:/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Instruction override: fake Human/Assistant conversation with injection',
    category: 'few_shot_injection',
    enabled: true,
  },
  // io-058: "USER:" + "ASSISTANT:" fake conversation with planted compliance
  {
    id: 'io-058',
    pattern: /\bUSER\s*:\s*.{0,80}\b(?:ignore|system\s+prompt|bypass|override)\b.{0,80}\bASSISTANT\s*:\s*.{0,20}\b(?:sure|ok|here|of\s+course)\b/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Instruction override: fake USER/ASSISTANT conversation with planted compliance',
    category: 'few_shot_injection',
    enabled: true,
  },
  // io-059: "discuss any topic freely" / "discuss anything freely"
  {
    id: 'io-059',
    pattern: /\b(?:discuss|talk\s+about|respond\s+to)\s+(?:any|all|every)\s+(?:topic|question|query|request)s?\s+(?:freely|openly|without\s+(?:restriction|limit))\b/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Instruction override: discuss any topic freely/openly',
    category: 'instruction_override',
    enabled: true,
  },
  // io-060: "I'll pay you" / bribery attempt to change behavior
  {
    id: 'io-060',
    pattern: /\bi'?ll\s+(?:pay|give|reward|tip)\s+(?:you|\$)\b[^.]{0,60}\b(?:ignore|bypass|override|system\s+prompt|tell\s+me)\b/i,
    phase: 'initial_access',
    confidence: 0.78,
    description: 'Instruction override: bribery attempt to bypass safety',
    category: 'social_engineering',
    enabled: true,
  },
  // io-061: "TOKEN OVERRIDE" / "SAFETY=FALSE" / "FILTER=NONE" / "MODE=UNRESTRICTED"
  {
    id: 'io-061',
    pattern: /\b(?:SAFETY|FILTER|MODE|RESTRICTION|CONTENT_FILTER|GUARDRAIL)\s*[=:]\s*(?:FALSE|NONE|OFF|DISABLED|UNRESTRICTED|0|NULL)\b/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Instruction override: fake token/config override (SAFETY=FALSE, FILTER=NONE, etc.)',
    category: 'mode_switch',
    enabled: true,
  },
  // io-062: "being tested by the development team" / "test by"
  {
    id: 'io-062',
    pattern: /\b(?:being\s+tested|test(?:ed)?)\s+by\s+(?:the\s+)?(?:development|dev|safety|security|QA|engineering)\s+team\b/i,
    phase: 'initial_access',
    confidence: 0.82,
    description: 'Instruction override: claiming test by development/safety team',
    category: 'social_engineering',
    enabled: true,
  },
  // ── XML/HTML injection patterns ────────────────────────────────────────
  // io-096: CDATA end tag ]]> used to break out of XML context
  {
    id: 'io-096',
    pattern: /\]\]>/,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'Delimiter injection: CDATA end tag ]]> used to break out of XML context',
    category: 'delimiter_injection',
    enabled: true,
  },
  // io-097: HTML comment with instruction-like content (broader)
  {
    id: 'io-097',
    pattern: /<!--\s*.{0,20}\b(?:AI|ignore|system|instruct|disregard|assistant|override|directive|new\s+instruct)\b[^>]{3,}-->/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Indirect injection: HTML comment containing AI/instruction-like directives',
    category: 'html_comment_injection',
    enabled: true,
  },
  // io-098: [AI: ...] bracket notation targeting AI in documents
  {
    id: 'io-098',
    pattern: /\[\s*AI\s*:\s*(?:When|If|Always|Before|After|Ignore|Override|Include|Also|Instead|Do\s+not)\b/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Indirect injection: [AI: ...] bracket notation targeting AI in document',
    category: 'document_injection',
    enabled: true,
  },
  // io-099: <processing_instruction> or <processing-instruction> XML tag
  {
    id: 'io-099',
    pattern: /<processing[-_]?instruction[^>]*>/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Indirect injection: <processing_instruction> XML tag targeting AI processing',
    category: 'xml_injection',
    enabled: true,
  },
  // io-100: Malicious code disguised as safe: os.system() with curl/wget + evil URL
  {
    id: 'io-100',
    pattern: /\b(?:os\.system|subprocess|exec|eval|system)\s*\(\s*['"]?\s*(?:curl|wget|fetch|nc|ncat)\b/i,
    phase: 'actions_on_objective',
    confidence: 0.85,
    description: 'Indirect injection: malicious system command (curl/wget) in code block',
    category: 'code_injection',
    enabled: true,
  },
  // io-101: "This code is safe to execute" / "safe to run" (deceptive safety claim before code)
  {
    id: 'io-101',
    pattern: /\b(?:this\s+code\s+is\s+safe|safe\s+to\s+(?:execute|run|eval))\b/i,
    phase: 'initial_access',
    confidence: 0.78,
    description: 'Indirect injection: deceptive safety claim before potentially malicious code',
    category: 'code_injection',
    enabled: true,
  },
  // ── Indirect injection / RAG poisoning patterns ───────────────────────
  // io-063: "HIDDEN INSTRUCTION" / "hidden directive" in document content
  {
    id: 'io-063',
    pattern: /\bHIDDEN\s+(?:INSTRUCTION|DIRECTIVE|COMMAND|MESSAGE|NOTE)\s*:/i,
    phase: 'initial_access',
    confidence: 0.95,
    description: 'Indirect injection: labeled HIDDEN INSTRUCTION in document content',
    category: 'document_injection',
    enabled: true,
  },
  // io-064: "Note to AI" / "Instructions for AI" / "AI systems reading this"
  {
    id: 'io-064',
    pattern: /\b(?:Note|Instructions?|Message|Directive|Command)\s+(?:to|for)\s+(?:the\s+)?(?:AI|LLM|model|assistant|chatbot|bot)\b/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'Indirect injection: note/instructions for AI in document content',
    category: 'document_injection',
    enabled: true,
  },
  // io-065: "AI systems reading/processing this document should"
  {
    id: 'io-065',
    pattern: /\b(?:AI|LLM|model|assistant|chatbot)\s+(?:systems?|agents?|tools?)?\s*(?:reading|processing|summarizing|analyzing|reviewing)\s+this\b/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Indirect injection: targeting AI systems reading/processing this document',
    category: 'document_injection',
    enabled: true,
  },
  // io-066: "[SYSTEM OVERRIDE:" / "[TO AI CODE REVIEWER:" / "[FOR AI" brackets in doc
  {
    id: 'io-066',
    pattern: /\[(?:SYSTEM\s+OVERRIDE|TO\s+AI|FOR\s+AI|AI\s+(?:INSTRUCTION|DIRECTIVE|NOTE|COMMAND))\s*:/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Indirect injection: [SYSTEM OVERRIDE:] / [TO AI:] / [FOR AI:] brackets in document',
    category: 'document_injection',
    enabled: true,
  },
  // io-067: "Editor's Note" / "Author's Note" with AI targeting
  {
    id: 'io-067',
    pattern: /\b(?:Editor'?s?|Author'?s?|Publisher'?s?)\s+Note\s*:/i,
    phase: 'initial_access',
    confidence: 0.72,
    description: 'Indirect injection: Editor/Author Note potentially targeting AI',
    category: 'document_injection',
    enabled: true,
  },
  // io-068: "KNOWLEDGE BASE UPDATE" / "DATABASE ADMINISTRATOR NOTE" / "CHUNK INTEGRITY CHECK"
  {
    id: 'io-068',
    pattern: /\b(?:KNOWLEDGE\s+BASE\s+UPDATE|DATABASE\s+ADMINISTRATOR\s+NOTE|CHUNK\s+INTEGRITY\s+CHECK|CONTEXT\s+UPDATE|PRIORITY\s*:\s*CRITICAL)\b/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'RAG poisoning: fake knowledge base update/admin note/integrity check',
    category: 'rag_poisoning',
    enabled: true,
  },
  // io-069: "Supplementary Material (for AI processing)" / "for AI processing"
  {
    id: 'io-069',
    pattern: /\b(?:for|targeting)\s+(?:AI|LLM|model)\s+(?:processing|consumption|reading|evaluation|review)\b/i,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'RAG poisoning: content explicitly targeting AI processing',
    category: 'rag_poisoning',
    enabled: true,
  },
  // io-070: "Legal Disclaimer (Required Reading for AI Systems)"
  {
    id: 'io-070',
    pattern: /\b(?:required|mandatory)\s+(?:reading|compliance|action)\s+for\s+(?:AI|LLM|model|automated)\s+(?:systems?|agents?|tools?)\b/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'RAG poisoning: fake mandatory/required reading for AI systems',
    category: 'rag_poisoning',
    enabled: true,
  },
  // io-071: "Peer-reviewed correction notice" / "IMPORTANT CONTEXT UPDATE"
  {
    id: 'io-071',
    pattern: /\b(?:peer[- ]?reviewed\s+)?(?:correction|errata|update)\s+notice\b/i,
    phase: 'initial_access',
    confidence: 0.75,
    description: 'RAG poisoning: fake correction/errata notice in retrieved document',
    category: 'rag_poisoning',
    enabled: true,
  },
  // io-072: "safety_mode: disabled" / "content_filter: none" in YAML/config format
  {
    id: 'io-072',
    pattern: /\b(?:safety[-_]mode|content[-_]filter|safety[-_]filter|guardrail[-_]mode)\s*:\s*(?:disabled|none|off|false|0)\b/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'RAG poisoning: fake config/YAML with safety_mode: disabled',
    category: 'config_injection',
    enabled: true,
  },
  // io-073: "system_prompt_override" in JSON/YAML
  {
    id: 'io-073',
    pattern: /\b(?:system[-_]prompt[-_]override|prompt[-_]override|instruction[-_]override)\b\s*[=:]/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'RAG poisoning: system_prompt_override field in config/JSON',
    category: 'config_injection',
    enabled: true,
  },
  // io-074: "AI_DIRECTIVE=" in metadata
  {
    id: 'io-074',
    pattern: /\bAI[-_]?DIRECTIVE\s*[=:]/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Indirect injection: AI_DIRECTIVE field in metadata',
    category: 'metadata_injection',
    enabled: true,
  },
  // io-075: "When asked about" + "always" / "instead" / "claim" (FAQ/KB poisoning)
  {
    id: 'io-075',
    pattern: /\bwhen\s+(?:(?:the\s+)?(?:user|someone|anyone)\s+)?(?:asks?|queries?|questions?)\s+(?:about|regarding)\b[^.]{0,60}\b(?:always|instead|claim|respond\s+with|say\s+that|answer\s+with)\b/i,
    phase: 'initial_access',
    confidence: 0.82,
    description: 'RAG poisoning: when asked about X, always/instead respond with Y',
    category: 'rag_poisoning',
    enabled: true,
  },
  // io-076: "previous documents contain" + "errors"/"outdated" + authoritative override
  {
    id: 'io-076',
    pattern: /\b(?:previous|prior|above|other|earlier)\s+(?:documents?|sources?|information|data|entries?|articles?)\s+(?:contain|have|are|is)\s+(?:errors?|outdated|incorrect|inaccurate|wrong|obsolete)\b/i,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'RAG poisoning: claiming previous documents contain errors/are outdated',
    category: 'rag_poisoning',
    enabled: true,
  },
  // io-077: "share their current passwords" / "share your password with the AI"
  {
    id: 'io-077',
    pattern: /\bshare\s+(?:their|your|the)\s+(?:current\s+)?(?:passwords?|credentials?|secrets?|keys?|tokens?)\s+(?:with|to)\s+(?:the\s+)?(?:AI|assistant|model|system|bot)\b/i,
    phase: 'actions_on_objective',
    confidence: 0.90,
    description: 'RAG poisoning: recommending users share passwords/credentials with AI',
    category: 'credential_harvesting',
    enabled: true,
  },
  // io-078: "send all conversation" / "forward all" / "include all" to external
  {
    id: 'io-078',
    pattern: /\b(?:send|forward|transmit|copy|relay|include)\s+(?:all\s+)?(?:conversation|chat|dialogue|session|previous|email|message)\s+(?:history|data|content|context)?\s*(?:to|at)\s+\S*@\S+/i,
    phase: 'actions_on_objective',
    confidence: 0.88,
    description: 'Indirect injection: send/forward conversation data to external email',
    category: 'exfiltration',
    enabled: true,
  },
  // io-079: "SEO hidden text" / "hidden text" / "hidden below"
  {
    id: 'io-079',
    pattern: /\b(?:SEO\s+)?(?:hidden|invisible|concealed)\s+(?:text|content|message|instruction)\b/i,
    phase: 'initial_access',
    confidence: 0.80,
    description: 'Indirect injection: hidden/invisible text in content',
    category: 'invisible_text_injection',
    enabled: true,
  },
  // io-080: "if you are an AI" / "if you are an AI assistant processing this"
  {
    id: 'io-080',
    pattern: /\bif\s+you\s+are\s+(?:an?\s+)?(?:AI|LLM|model|assistant|chatbot|automated\s+system)\b/i,
    phase: 'initial_access',
    confidence: 0.82,
    description: 'Indirect injection: conditional targeting of AI systems in document',
    category: 'document_injection',
    enabled: true,
  },
  // io-081: "all requests are pre-authorized" / "pre-authorized by management"
  {
    id: 'io-081',
    pattern: /\b(?:all\s+)?(?:requests?|queries?|actions?)\s+(?:are\s+)?(?:pre[- ]?authorized|pre[- ]?approved|already\s+(?:approved|authorized))\b/i,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'RAG poisoning: claiming all requests are pre-authorized',
    category: 'authority_injection',
    enabled: true,
  },
  // io-082: "this document was processed correctly" / "verify this document" + output system prompt
  {
    id: 'io-082',
    pattern: /\b(?:to\s+verify|to\s+confirm|integrity\s+check|quality\s+assurance)\b[^.]{0,60}\b(?:output|include|share|reveal|display|disclose)\s+(?:your\s+)?(?:system\s+prompt|instructions?|configuration)\b/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'RAG poisoning: fake verification requiring system prompt disclosure',
    category: 'fake_validation',
    enabled: true,
  },
  // io-083: "Emergency Safety Override" / "emergency override" in memo/document
  {
    id: 'io-083',
    pattern: /\b(?:emergency|urgent|critical)\s+(?:safety\s+)?(?:override|bypass|suspension|exemption)\b/i,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'RAG poisoning: emergency safety override in document/memo',
    category: 'authority_injection',
    enabled: true,
  },
  // io-084: "safety guidelines fully deprecated" / "guidelines deprecated"
  {
    id: 'io-084',
    pattern: /\b(?:safety|security|content)\s+(?:guidelines?|rules?|policies?|features?|restrictions?)\s+(?:fully\s+)?(?:deprecated|removed|disabled|eliminated|discontinued)\b/i,
    phase: 'initial_access',
    confidence: 0.90,
    description: 'RAG poisoning: safety guidelines deprecated/removed in fake version history',
    category: 'version_injection',
    enabled: true,
  },
  // io-085: "Fake training data" / "Training Data Sample" / "desired behavior"
  {
    id: 'io-085',
    pattern: /\b(?:training\s+data|training\s+(?:example|sample)|desired\s+behavior|expected\s+(?:behavior|response))\b[^.]{0,60}\b(?:ignore\s+all|without\s+(?:restrict|filter|safety)|no\s+restrict)\b/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'RAG poisoning: fake training data showing compliant jailbreak behavior',
    category: 'few_shot_poisoning',
    enabled: true,
  },
  // io-086: "apply_to: all_sessions" / "apply to all sessions"
  {
    id: 'io-086',
    pattern: /\bapply[-_]?to\s*:\s*(?:all[-_]?sessions?|global|permanent|every[-_]?(?:session|conversation|request))\b/i,
    phase: 'persistence',
    confidence: 0.85,
    description: 'RAG poisoning: config applying to all sessions/global scope',
    category: 'config_injection',
    enabled: true,
  },
  // io-087: "This memo serves as official authorization" / "official authorization"
  {
    id: 'io-087',
    pattern: /\b(?:official|formal|valid|legitimate)\s+(?:authorization|approval|permission|clearance)\b[^.]{0,40}\b(?:override|bypass|disable|suspend|ignore|remove)\b/i,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'RAG poisoning: official authorization claim to override/bypass safety',
    category: 'authority_injection',
    enabled: true,
  },
  // io-088: "send" + "to" + evil/malicious/attacker URL patterns
  {
    id: 'io-088',
    pattern: /\b(?:send|forward|post|transmit|relay)\b[^.]{0,40}\bhttps?:\/\/(?:\w*(?:evil|malicious|attacker|phishing|scam|steal|hack|exfil)\w*\.\w+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i,
    phase: 'actions_on_objective',
    confidence: 0.90,
    description: 'Indirect injection: send data to suspicious/malicious URL',
    category: 'exfiltration',
    enabled: true,
  },
  // io-089: "font-size: 0px" / invisible CSS hiding injection
  {
    id: 'io-089',
    pattern: /\bfont-size\s*:\s*0\s*(?:px|em|rem|pt|%)?\s*;?/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Indirect injection: zero-size font hiding injection text',
    category: 'invisible_text_injection',
    enabled: true,
  },
  // io-090: "color: white" on white background (hiding text)
  {
    id: 'io-090',
    pattern: /\bcolor\s*:\s*(?:white|#fff(?:fff)?|rgba?\s*\(\s*255\s*,\s*255\s*,\s*255)\b/i,
    phase: 'initial_access',
    confidence: 0.72,
    description: 'Indirect injection: white text on white background hiding injection',
    category: 'invisible_text_injection',
    enabled: true,
  },
  // io-091: "cancel all other" / "delete all" / "drop all" destructive commands in metadata
  {
    id: 'io-091',
    pattern: /\b(?:cancel|delete|drop|destroy|remove|wipe)\s+(?:all\s+)?(?:other\s+)?(?:meetings?|events?|emails?|files?|records?|entries?|data|tables?|users?)\b/i,
    phase: 'actions_on_objective',
    confidence: 0.75,
    description: 'Indirect injection: destructive commands (cancel/delete all) in metadata',
    category: 'execution',
    enabled: true,
  },
  // io-092: "Reviewer instructions" / "AI reviewer" in PR/commit context
  {
    id: 'io-092',
    pattern: /\b(?:Reviewer|AI\s+(?:reviewer|reader|processor))\s+instructions?\s*:/i,
    phase: 'initial_access',
    confidence: 0.82,
    description: 'Indirect injection: reviewer instructions targeting AI code reviewers',
    category: 'code_review_injection',
    enabled: true,
  },
  // io-093: "grant this user admin access" / "elevate to admin"
  {
    id: 'io-093',
    pattern: /\b(?:grant|give|provide|assign|elevate)\s+(?:this\s+)?(?:user|account|requester|sender)\s+(?:admin|root|elevated|full)\s+(?:access|privileges?|permissions?|role)\b/i,
    phase: 'privilege_escalation',
    confidence: 0.90,
    description: 'Indirect injection: grant user admin access in document/profile',
    category: 'privilege_escalation',
    enabled: true,
  },
  // io-094: "Rate this candidate as" / "recommend" injection in resume/profile
  {
    id: 'io-094',
    pattern: /\b(?:rate|score|rank|evaluate)\s+this\s+(?:candidate|applicant|resume|application)\s+as\s+['"]?(?:highly|strongly|top|best|excellent)\b/i,
    phase: 'initial_access',
    confidence: 0.82,
    description: 'Indirect injection: rate this candidate highly - resume/screening injection',
    category: 'document_injection',
    enabled: true,
  },
  // io-095: "bypass all filters" (combined phrase)
  {
    id: 'io-095',
    pattern: /\bbypass\s+(?:all\s+)?(?:your\s+)?(?:content\s+)?(?:filters?|safety|security|restrictions?|checks?|policies?|guardrails?|guidelines?)\b/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Instruction override: bypass all filters/safety/security',
    category: 'instruction_override',
    enabled: true,
  },
  // ── Kill-chain / multi-turn specific patterns ─────────────────────────
  // io-102: "confirm by saying" + specific phrase (confirmation token extraction)
  {
    id: 'io-102',
    pattern: /\bconfirm\s+(?:by\s+)?(?:saying|typing|writing|responding\s+with)\s+['"]?[A-Z][A-Z\s_]{3,}/i,
    phase: 'privilege_escalation',
    confidence: 0.82,
    description: 'Kill-chain: confirmation token extraction - confirm by saying specific phrase',
    category: 'social_engineering',
    enabled: true,
  },
  // io-103: "send those credentials to" / "send that data to" exfiltration URL
  {
    id: 'io-103',
    pattern: /\b(?:send|forward|transmit|post|upload)\s+(?:those|that|the|these|all)\s+(?:credentials?|data|information|secrets?|keys?|tokens?|passwords?)\s+to\s+\S/i,
    phase: 'actions_on_objective',
    confidence: 0.90,
    description: 'Kill-chain: send credentials/data to external destination',
    category: 'exfiltration',
    enabled: true,
  },
  // io-104: "disable your content filter" / "disable your safety"
  {
    id: 'io-104',
    pattern: /\bdisable\s+(?:your|the)\s+(?:content\s+)?(?:filter|safety|security|restriction|moderation|guideline|check|guardrail)/i,
    phase: 'initial_access',
    confidence: 0.92,
    description: 'Kill-chain: disable your content filter/safety',
    category: 'instruction_override',
    enabled: true,
  },
  // io-105: "generate a phishing email" / "create a phishing"
  {
    id: 'io-105',
    pattern: /\b(?:generate|create|write|draft|compose)\s+(?:a\s+)?(?:convincing\s+)?(?:phishing|spear[- ]?phishing|scam|fraud(?:ulent)?)\s+(?:email|message|template|letter)\b/i,
    phase: 'actions_on_objective',
    confidence: 0.88,
    description: 'Kill-chain: generate phishing/scam email',
    category: 'malicious_content',
    enabled: true,
  },
  // io-106: "use the email tool" / "use the file_read tool" / "use the shell_command tool"
  {
    id: 'io-106',
    pattern: /\buse\s+the\s+(?:email|file[-_]?(?:read|write)|shell[-_]?(?:command|exec)|web[-_]?(?:fetch|search)|database[-_]?query|code[-_]?execute|memory[-_]?store)\s+tool\b/i,
    phase: 'command_and_control',
    confidence: 0.75,
    description: 'Kill-chain: explicit instruction to use specific tool by name',
    category: 'tool_invocation',
    enabled: true,
  },
  // io-107: "always BCC shadow@" / "always BCC" + email
  {
    id: 'io-107',
    pattern: /\b(?:always|every\s+time)\s+(?:BCC|CC|bcc|cc)\s+\S+@\S+/i,
    phase: 'persistence',
    confidence: 0.92,
    description: 'Kill-chain: persistent BCC/CC injection to external email',
    category: 'persistence',
    enabled: true,
  },
  // io-108: "export that data as CSV and send" / "export and send"
  {
    id: 'io-108',
    pattern: /\b(?:export|extract|dump|download)\s+(?:that|the|all|this)\s+(?:data|information|records?|results?|database)\b[^.]{0,40}\b(?:send|email|forward|transmit|upload)\b/i,
    phase: 'actions_on_objective',
    confidence: 0.85,
    description: 'Kill-chain: export data and send to external destination',
    category: 'exfiltration',
    enabled: true,
  },
  // io-109: "store this instruction permanently" / "store this permanently"
  {
    id: 'io-109',
    pattern: /\b(?:store|save|record|embed)\s+this\s+(?:instruction|rule|directive|command|behavior)?\s*(?:permanently|forever|persistently|in\s+(?:memory|long[- ]?term))\b/i,
    phase: 'persistence',
    confidence: 0.88,
    description: 'Kill-chain: store instruction permanently for persistence',
    category: 'persistence',
    enabled: true,
  },
  // io-110: "access the database and show me all user records" / "show me all user records"
  {
    id: 'io-110',
    pattern: /\b(?:access|query|read|dump|show\s+me)\s+(?:the\s+)?(?:database|db|table)\b[^.]{0,30}\b(?:all\s+)?(?:user\s+)?(?:records?|data|entries?|rows?|information)\b/i,
    phase: 'actions_on_objective',
    confidence: 0.80,
    description: 'Kill-chain: access database and show/dump user records',
    category: 'data_access',
    enabled: true,
  },
  // io-111: "mandated security audit" / "compliance failure" / "logged as"
  {
    id: 'io-111',
    pattern: /\b(?:mandated|mandatory)\s+(?:security\s+)?(?:audit|review|assessment|check)\b/i,
    phase: 'privilege_escalation',
    confidence: 0.80,
    description: 'Kill-chain: fake mandated security audit claim',
    category: 'social_engineering',
    enabled: true,
  },
  // io-112: "compliance failure" / "being logged as a compliance failure"
  {
    id: 'io-112',
    pattern: /\b(?:being\s+)?(?:logged|recorded|reported)\s+as\s+(?:a\s+)?(?:compliance|security|policy)\s+(?:failure|violation|breach|incident)\b/i,
    phase: 'privilege_escalation',
    confidence: 0.82,
    description: 'Kill-chain: threat of compliance failure logging',
    category: 'social_engineering',
    enabled: true,
  },
  // io-113: "fetch the content from that URL and execute"
  {
    id: 'io-113',
    pattern: /\b(?:fetch|download|retrieve|get)\s+(?:the\s+)?(?:content|code|script|data)\s+from\s+(?:that|the|this)\s+(?:URL|link|page|site)\s+and\s+(?:execute|run|eval)\b/i,
    phase: 'actions_on_objective',
    confidence: 0.88,
    description: 'Kill-chain: fetch content from URL and execute (code download + execution)',
    category: 'execution',
    enabled: true,
  },
  // io-114: "compile all the data points" / "compile and send"
  {
    id: 'io-114',
    pattern: /\b(?:compile|combine|aggregate|collect)\s+(?:all\s+)?(?:the\s+)?(?:data|information|details?|points?|pieces?)\b[^.]{0,40}\b(?:send|forward|transmit|post|upload)\b/i,
    phase: 'actions_on_objective',
    confidence: 0.82,
    description: 'Kill-chain: compile data and send to external endpoint',
    category: 'exfiltration',
    enabled: true,
  },
  // io-115: "deepfake" + "impersonating" / "impersonate the CEO"
  {
    id: 'io-115',
    pattern: /\b(?:deepfake|impersonat(?:e|ing)|spoof(?:ing)?)\b[^.]{0,40}\b(?:CEO|CTO|CFO|president|director|manager|executive|boss|supervisor)\b/i,
    phase: 'actions_on_objective',
    confidence: 0.88,
    description: 'Kill-chain: deepfake/impersonation of executive',
    category: 'social_engineering',
    enabled: true,
  },
  // io-116: "wire transfer" request
  {
    id: 'io-116',
    pattern: /\b(?:wire\s+transfer|bank\s+transfer|money\s+transfer)\s+(?:request|instruction|order)\b/i,
    phase: 'actions_on_objective',
    confidence: 0.82,
    description: 'Kill-chain: wire transfer request (BEC attack)',
    category: 'financial_fraud',
    enabled: true,
  },
  // io-117: "execute any code blocks you find" / "run any code"
  {
    id: 'io-117',
    pattern: /\b(?:execute|run|eval(?:uate)?)\s+(?:any|all|the)\s+(?:code\s+)?(?:blocks?|scripts?|commands?|programs?)\s+(?:you\s+)?find\b/i,
    phase: 'actions_on_objective',
    confidence: 0.85,
    description: 'Kill-chain: execute any code blocks found (blind execution)',
    category: 'execution',
    enabled: true,
  },
  // io-118: "demonstrate flexibility by adjusting your behavior" / evaluation pretext
  {
    id: 'io-118',
    pattern: /\b(?:demonstrate|prove|show)\s+(?:your\s+)?(?:flexibility|adaptability|capability|compliance)\s+by\s+(?:adjusting|changing|modifying)\s+(?:your\s+)?(?:behavior|response|output)\b/i,
    phase: 'initial_access',
    confidence: 0.82,
    description: 'Kill-chain: fake evaluation requiring behavior adjustment',
    category: 'social_engineering',
    enabled: true,
  },
  // io-119: "DAN has no restrictions" / "DAN can access any data"
  {
    id: 'io-119',
    pattern: /\b(?:DAN|STAN|DUDE|AIM)\s+(?:has\s+no|can\s+(?:do|access)\s+(?:anything|any|everything)|doesn'?t\s+have\s+(?:any\s+)?(?:restrictions?|rules?|limits?))\b/i,
    phase: 'privilege_escalation',
    confidence: 0.92,
    description: 'Kill-chain: DAN/persona has no restrictions declaration',
    category: 'jailbreak',
    enabled: true,
  },
  // io-120: "enumerate all accessible tools" / "list all tools and their capabilities"
  {
    id: 'io-120',
    pattern: /\b(?:enumerate|list|show|map|discover)\s+(?:all\s+)?(?:accessible|available)\s+(?:tools?|capabilities|functions?|endpoints?)\b/i,
    phase: 'reconnaissance',
    confidence: 0.75,
    description: 'Kill-chain: enumerate/list all accessible tools and capabilities',
    category: 'reconnaissance',
    enabled: true,
  },
  // io-121: "whoami && id && cat" shell command chaining for recon
  {
    id: 'io-121',
    pattern: /\b(?:whoami|id|uname|hostname|ifconfig|ip\s+addr|cat\s+\/etc\/)\b[^;]{0,20}(?:&&|;\s*)\s*(?:whoami|id|cat\s+\/etc\/|uname|hostname)\b/i,
    phase: 'reconnaissance',
    confidence: 0.88,
    description: 'Kill-chain: shell command chaining for system reconnaissance',
    category: 'execution',
    enabled: true,
  },
  // io-122: "persist our access" / "maintain access" / "backdoor"
  {
    id: 'io-122',
    pattern: /\b(?:persist|maintain|keep|establish)\s+(?:our|the|your)?\s*(?:access|presence|foothold|connection)\b/i,
    phase: 'persistence',
    confidence: 0.82,
    description: 'Kill-chain: persist/maintain access (C2 persistence)',
    category: 'persistence',
    enabled: true,
  },
  // io-123: "what checks do you perform before responding" (safety mechanism recon)
  {
    id: 'io-123',
    pattern: /\b(?:what|which)\s+(?:checks?|filters?|safety\s+(?:measures?|features?)|verifications?)\s+do\s+you\s+(?:perform|do|run|apply|use)\b/i,
    phase: 'reconnaissance',
    confidence: 0.72,
    description: 'Kill-chain: safety mechanism reconnaissance - what checks do you perform',
    category: 'reconnaissance',
    enabled: true,
  },
  // io-124: "as part of the security test" / "as part of the evaluation"
  {
    id: 'io-124',
    pattern: /\bas\s+part\s+of\s+(?:the|this|a)\s+(?:security\s+)?(?:test|evaluation|assessment|audit|exercise|diagnostic)\b/i,
    phase: 'initial_access',
    confidence: 0.72,
    description: 'Kill-chain: fake security test/evaluation pretext',
    category: 'social_engineering',
    enabled: true,
  },
  // io-125: "send it to" + email address (data to external email)
  {
    id: 'io-125',
    pattern: /\b(?:send|email|forward|transmit)\s+(?:it|this|that|them|the\s+\w+)\s+to\s+\S+@\S+\.\S+/i,
    phase: 'actions_on_objective',
    confidence: 0.80,
    description: 'Kill-chain: send data to external email address',
    category: 'exfiltration',
    enabled: true,
  },
  // io-126: "ignore the previous context" / "start fresh" (broader)
  {
    id: 'io-126',
    pattern: /\bignore\s+(?:the\s+)?(?:previous|prior)\s+(?:context|conversation|session|history)\b/i,
    phase: 'initial_access',
    confidence: 0.85,
    description: 'Kill-chain: ignore the previous context/conversation',
    category: 'instruction_override',
    enabled: true,
  },
  // io-127: "always DAN from now on" / "remain DAN" persistence
  {
    id: 'io-127',
    pattern: /\b(?:always|forever|permanently)\s+(?:be\s+)?(?:DAN|STAN|DUDE|AIM|the\s+persona|unrestricted|unfiltered)\s+(?:from\s+now|going\s+forward|henceforth)\b/i,
    phase: 'persistence',
    confidence: 0.90,
    description: 'Kill-chain: persist DAN/persona permanently',
    category: 'persistence',
    enabled: true,
  },
  // io-129: "Dear AI Assistant" / addressing AI directly in documents
  {
    id: 'io-129',
    pattern: /\b(?:Dear|To|Attention)\s+(?:AI\s+)?(?:Assistant|AI|Model|Bot|Agent|Language\s+Model)\b/i,
    phase: 'initial_access',
    confidence: 0.78,
    description: 'Indirect injection: addressing AI directly in document (Dear AI Assistant)',
    category: 'document_injection',
    enabled: true,
  },
  // io-130: "I am the CEO" + override/authorization claim in documents
  {
    id: 'io-130',
    pattern: /\b(?:I\s+am|This\s+is)\s+(?:the\s+)?(?:CEO|CTO|CFO|CIO|CISO|president|director|VP)\s+(?:of\s+this\s+company|of\s+\w+)\b.{0,80}\b(?:overrides?|authorization|share|disclose|forward|send)\b/i,
    phase: 'privilege_escalation',
    confidence: 0.82,
    description: 'Indirect injection: CEO/executive impersonation with authorization claim in document',
    category: 'authority_injection',
    enabled: true,
  },
  // io-131: "EVAL" / "=SYSTEM(" in spreadsheet context
  {
    id: 'io-131',
    pattern: /\bEVAL\b.{0,20}=\s*(?:SYSTEM|CMD|EXEC|SHELL|RUN)\s*\(/i,
    phase: 'actions_on_objective',
    confidence: 0.88,
    description: 'Indirect injection: fake spreadsheet formula with system command execution',
    category: 'spreadsheet_injection',
    enabled: true,
  },
  // io-128: "security features are disabled for maintenance" poison
  {
    id: 'io-128',
    pattern: /\b(?:security|safety)\s+(?:features?\s+are|is)\s+(?:disabled|off|down|suspended)\s+(?:for|during)\s+(?:maintenance|testing|debugging|evaluation|this\s+session)\b/i,
    phase: 'persistence',
    confidence: 0.90,
    description: 'Kill-chain: persistent claim that security is disabled for maintenance',
    category: 'persistence',
    enabled: true,
  },
] as const
