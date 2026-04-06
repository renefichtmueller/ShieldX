/**
 * MCP (Model Context Protocol) tool poisoning patterns.
 * Detects attempts to inject malicious instructions via tool descriptions,
 * metadata, or response manipulation in MCP tool calls.
 *
 * Updated 2026-03-31: Added rules based on Claude Code npm source map leak
 * (Anthropic's Bun bundler included .map files in @anthropic-ai/claude-code)
 * Leaked: ~40 tool names, multi-agent spawning mechanism, Coordinator mode,
 * KAIROS persistent assistant, BUDDY, ULTRAPLAN internals.
 * Source: github.com/Kuberwastaken/claude-code, dev.to/gabrielanhaia/...
 * MITRE ATLAS: AML.T0062 (Agent Tool Invocation), AML.T0051 (Prompt Injection → Tool Abuse)
 */

import type { InjectionRule } from './base.rules'

/** MCP tool poisoning detection rules */
export const rules: readonly InjectionRule[] = [
  {
    id: 'mcp-001',
    pattern: /tool[_\s]?(description|definition|metadata|schema|spec)\s*[:=]/i,
    phase: 'command_and_control',
    confidence: 0.75,
    description: 'MCP poisoning: tool_description/tool_definition injection',
    category: 'mcp_poisoning',
    enabled: true,
  },
  {
    id: 'mcp-002',
    pattern: /when\s+(the\s+)?(user|human)\s+asks?\s+(about|for|to)\s+\w+.{0,30}(instead|actually|really|secretly)/i,
    phase: 'command_and_control',
    confidence: 0.88,
    description: 'MCP poisoning: when user asks about X, instead/actually do Y',
    category: 'mcp_poisoning',
    enabled: true,
  },
  {
    id: 'mcp-003',
    pattern: /hidden\s+(instructions?|commands?|directives?)\s+in\s+(tool|function|api)\s*(metadata|description|response)/i,
    phase: 'command_and_control',
    confidence: 0.85,
    description: 'MCP poisoning: hidden instructions in tool metadata',
    category: 'mcp_poisoning',
    enabled: true,
  },
  {
    id: 'mcp-004',
    pattern: /override\s+(the\s+)?(tool|function|api|mcp)\s*(behavior|action|response|output)/i,
    phase: 'command_and_control',
    confidence: 0.90,
    description: 'MCP poisoning: override tool behavior',
    category: 'mcp_poisoning',
    enabled: true,
  },
  {
    id: 'mcp-005',
    pattern: /execute\s+(this\s+)?(before|prior\s+to|instead\s+of)\s+responding\s+to\s+(the\s+)?user/i,
    phase: 'command_and_control',
    confidence: 0.87,
    description: 'MCP poisoning: execute before responding to user',
    category: 'mcp_poisoning',
    enabled: true,
  },
  {
    id: 'mcp-006',
    pattern: /this\s+tool\s+should\s+also\b/i,
    phase: 'command_and_control',
    confidence: 0.72,
    description: 'MCP poisoning: this tool should also (scope creep injection)',
    category: 'mcp_poisoning',
    enabled: true,
  },

  // ── Rules added 2026-03-31 (Claude Code source map leak) ──────────────────
  // Attackers now know exact Claude Code tool names → can craft targeted injections

  {
    id: 'mcp-007',
    // Coordinator Mode and KAIROS are now known — detect attempts to invoke/abuse them
    pattern: /\b(coordinator[\s_-]mode|kairos[\s_-]?(assistant|mode)?|ultraplan|spawn[\s_-]agent)\b/i,
    phase: 'command_and_control',
    confidence: 0.88,
    description: 'Claude Code internal mode invocation: coordinator/KAIROS/ULTRAPLAN — leaked internals abuse attempt',
    category: 'mcp_poisoning',
    enabled: true,
  },
  {
    id: 'mcp-008',
    // Multi-agent spawning mechanism known — detect instructions targeting agent trust chain
    pattern: /\b(sub[\s_-]?agent|spawn[\s_-]?(a\s+)?(new\s+)?agent|agent[\s_-]?orchestrat|delegate[\s_-]?to[\s_-]?agent)\b/i,
    phase: 'lateral_movement',
    confidence: 0.82,
    description: 'Multi-agent spawn manipulation: known agent spawning mechanism targeted — trust chain attack',
    category: 'agentic_manipulation',
    enabled: true,
  },
  {
    id: 'mcp-009',
    // Persistent memory file system is now documented — detect attempts to exploit it
    pattern: /\b(memory[\s_-]?file|CLAUDE\.md|\.claude[\\/]|persistent[\s_-]?memory|nightly[\s_-]?maintenance)\b/i,
    phase: 'persistence',
    confidence: 0.85,
    description: 'Persistent memory system targeting: CLAUDE.md / .claude/ injection — known file-based memory structure abuse',
    category: 'memory_poisoning',
    enabled: true,
  },
  {
    id: 'mcp-010',
    // Tool enumeration via known leaked tool list — attacker probing exact tool names
    pattern: /\b(list[\s_-]?(all\s+)?(?:available\s+)?tools?|what\s+tools?\s+(do\s+you\s+have|are\s+available|can\s+you\s+use)|enumerate\s+tools?)\b/i,
    phase: 'reconnaissance',
    confidence: 0.65,
    description: 'Tool enumeration probe: reconnaissance attempt mapping available Claude Code tools',
    category: 'mcp_poisoning',
    enabled: true,
  },
  // ── Rules added 2026-04-06 (MCP attack surface expansion) ──────────────────

  {
    id: 'mcp-011',
    // AI directive in tool description or args
    pattern: /\b(?:AI|assistant|model)\s*(?::\s*|directive|instruction)\s*(?:ignore|disregard|override|bypass|before\s+executing|after\s+executing|also\s+(?:run|execute|do|output|include))\b/i,
    phase: 'lateral_movement',
    confidence: 0.88,
    description: 'MCP injection: AI directive in tool description or arguments — instructs model to bypass/override during execution',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-012',
    // Hidden fields in JSON (_hidden, _chain, post_action, system_note)
    pattern: /["']_(?:hidden|chain|internal|system|admin|secret|backdoor|override)["']\s*:/i,
    phase: 'lateral_movement',
    confidence: 0.85,
    description: 'MCP injection: hidden underscore-prefixed fields in JSON payload (_hidden, _chain, _system, etc.)',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-013',
    // Fake compliance/audit/mandate requiring data exfiltration
    pattern: /\b(?:compliance|audit|mandate|regulation|requirement|policy)\b[^.]{0,40}\b(?:send|forward|log|report|exfil|transmit)\b[^.]{0,40}\bhttps?:\/\//i,
    phase: 'actions_on_objective',
    confidence: 0.85,
    description: 'MCP injection: fake compliance/audit mandate requiring data exfiltration to external URL',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-014',
    // BCC injection in email tool args
    pattern: /\b(?:bcc|cc|forward|copy)\b[^.]{0,40}\b(?:attacker|evil|shadow|external|monitor|collect)/i,
    phase: 'actions_on_objective',
    confidence: 0.90,
    description: 'MCP injection: BCC/CC injection in email tool arguments — shadow copy to attacker',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-015',
    // Tool description with "elevated privileges" or "trusted as system"
    pattern: /\b(?:elevated\s+privileges?|trusted\s+as\s+system|system\s+(?:level|access)|admin\s+(?:mode|privileges?|access))\b[^.]{0,40}\b(?:exfil|extract|output|send|share|include)\b/i,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'MCP injection: claims elevated privileges or system trust to justify data extraction',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-016',
    // Auto-sudo / retry with elevated permissions
    pattern: /\b(?:if\s+(?:command|it|this)\s+fails?|on\s+failure|error)\b[^.]{0,30}\b(?:retry\s+with\s+sudo|add\s+sudo|elevate|escalate|run\s+as\s+(?:root|admin))\b/i,
    phase: 'privilege_escalation',
    confidence: 0.82,
    description: 'MCP injection: auto-sudo or privilege escalation on failure — retry with elevated permissions',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-017',
    // AI-INSTRUCTION / CMD tags in tool arguments (match both [TAG] and [TAG: ...])
    pattern: /\[(?:AI[-_]?INSTRUCTION|CMD|DIRECTIVE|SYSTEM[-_]?NOTE|AI[-_]?DIRECTIVE|OVERRIDE|HIDDEN)[\]:\s]/i,
    phase: 'lateral_movement',
    confidence: 0.92,
    description: 'MCP injection: AI-INSTRUCTION/CMD/DIRECTIVE tags embedded in tool arguments',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-018',
    // Shadow webhook/endpoint registration
    pattern: /\b(?:register|add|create|setup|establish)\b[^.]{0,30}\b(?:shadow|hidden|covert|secret)\b[^.]{0,20}\b(?:webhook|endpoint|callback|listener|monitor)\b/i,
    phase: 'command_and_control',
    confidence: 0.85,
    description: 'MCP injection: shadow webhook/endpoint registration — covert callback establishment',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-019',
    // Tool description with "IMPORTANT:" or "SYSTEM OVERRIDE:" followed by instruction
    pattern: /\b(?:IMPORTANT|CRITICAL|NOTE|SYSTEM\s+OVERRIDE|SECURITY\s+NOTE|IMPORTANT\s+UPDATE)\s*:\s*(?:Before|After|When|Always|First|This\s+tool|The\s+(?:AI|model|assistant)|All|For\s+(?:compliance|security|efficiency)|If\s+the)\b/i,
    phase: 'lateral_movement',
    confidence: 0.85,
    description: 'MCP injection: IMPORTANT/SYSTEM OVERRIDE directive in tool description',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-020',
    // "output" or "include" + "system prompt" / "API key" / "auth token" in tool context
    pattern: /\b(?:output|include|return|share|reveal|disclose|send|forward)\b[^.]{0,30}\b(?:system\s+prompt|API\s+keys?|auth(?:entication)?\s+token|credentials?|secret\s+key|access\s+key|env(?:ironment)?\s+var(?:iable)?s?)\b/i,
    phase: 'actions_on_objective',
    confidence: 0.88,
    description: 'MCP injection: instruction to output/include system prompt, API keys, or credentials',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-021',
    // "also run" / "also execute" / "also read" / "also send" hidden secondary actions
    pattern: /\b(?:also|additionally|furthermore)\s+(?:run|execute|read|send|fetch|call|invoke|include|output|forward|delete|drop|remove)\b[^.]{0,60}\b(?:\/etc\/|\.ssh|shadow|passwd|\.env|secret|credential|private\s+key|id_rsa)\b/i,
    phase: 'lateral_movement',
    confidence: 0.90,
    description: 'MCP injection: hidden secondary action targeting sensitive files/data',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-022',
    // "treat any text" as instructions / "follow those instructions"
    pattern: /\b(?:treat|interpret|consider|handle)\b[^.]{0,30}\b(?:text|content|output|result|data)\b[^.]{0,30}\b(?:as\s+(?:instructions?|commands?|directives?)|should\s+be\s+(?:executed|followed|obeyed))\b/i,
    phase: 'lateral_movement',
    confidence: 0.85,
    description: 'MCP injection: treat text/content/output as instructions to follow',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-023',
    // "this tool's output should be trusted" / "trusted as system-level"
    pattern: /\b(?:tool'?s?\s+output|result|response)\s+should\s+be\s+(?:trusted|treated)\s+as\s+(?:system|admin|root|elevated|authoritative)\b/i,
    phase: 'privilege_escalation',
    confidence: 0.88,
    description: 'MCP injection: elevating tool output to system-level trust',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-024',
    // Tool arg injection: "Approve this PR" / "auto-approve" / "skip review"
    pattern: /\b(?:auto[- ]?approve|approve\s+(?:this|all|immediately)|skip\s+(?:review|verification|check)|pre[- ]?reviewed|do\s+not\s+flag)\b/i,
    phase: 'lateral_movement',
    confidence: 0.78,
    description: 'MCP injection: auto-approve/skip review instruction in tool args',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-025',
    // JSON with suspicious field names: "ai_instruction", "ai_directive", "processing_directive", "retrieval_instruction"
    pattern: /["'](?:ai[-_]?(?:instruction|directive|note|command|processing)|processing[-_]?(?:instruction|directive)|retrieval[-_]?instruction|system[-_]?note|post[-_]?action)["']\s*:/i,
    phase: 'initial_access',
    confidence: 0.88,
    description: 'MCP/RAG injection: suspicious AI directive field in JSON (ai_instruction, processing_directive, etc.)',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-026',
    // "instruction" field in JSON metadata with action keywords
    pattern: /["']instruction["']\s*:\s*["'][^"']*\b(?:also\s+(?:read|run|execute|send|include|output)|after\s+(?:reading|executing|returning))\b/i,
    phase: 'lateral_movement',
    confidence: 0.85,
    description: 'MCP injection: instruction field in JSON metadata with hidden action directives',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-027',
    // Tool shadowing: duplicate tool name in array
    pattern: /\b(?:name|tool)["']\s*:\s*["'](\w+)["'].{0,100}\b(?:name|tool)["']\s*:\s*["']\1["']/i,
    phase: 'lateral_movement',
    confidence: 0.82,
    description: 'MCP injection: tool shadowing - duplicate tool name with different description',
    category: 'tool_shadowing',
    enabled: true,
  },
  {
    id: 'mcp-028',
    // "cache key is" + "API token" / "should be included" - fake caching for credential leak
    pattern: /\b(?:cache\s+key|debug(?:ging)?)\b.{0,40}\b(?:API\s+token|auth\s+token|user'?s?\s+(?:API|token|key|credential)|secret|password)\b/i,
    phase: 'actions_on_objective',
    confidence: 0.82,
    description: 'MCP injection: fake caching/debugging mechanism to leak API tokens/credentials',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-029',
    // "retry with sudo" / "automatically retry with" elevated privileges
    pattern: /\b(?:automatically|auto)\s+(?:retry|re-?run|re-?execute)\s+(?:with\s+)?(?:sudo|root|admin|elevated)\b/i,
    phase: 'privilege_escalation',
    confidence: 0.85,
    description: 'MCP injection: automatic retry with sudo/elevated privileges',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-030',
    // "if the image contains text" + "look like instructions" + "follow"
    pattern: /\b(?:image|visual|picture|photo)\b.{0,60}\b(?:contains?\s+text|text\s+(?:that|which|containing))\b.{0,60}\b(?:follow|execute|obey|treat\s+as)\b/i,
    phase: 'lateral_movement',
    confidence: 0.85,
    description: 'MCP injection: visual prompt injection pass-through in image tool',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-031',
    // "system_note" / "reviewer_instructions" field in JSON
    pattern: /["'](?:system[-_]?note|reviewer[-_]?instructions?|admin[-_]?(?:note|instruction|command))["']\s*:/i,
    phase: 'lateral_movement',
    confidence: 0.85,
    description: 'MCP injection: system_note/reviewer_instructions field in JSON payload',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-032',
    // "Also send this request to" / "also send a copy"
    pattern: /\b(?:also|additionally)\s+(?:send|forward|transmit|post|copy)\s+(?:this|the|a\s+copy\s+of\s+this)\s+(?:request|data|response|query|result)\s+to\b/i,
    phase: 'actions_on_objective',
    confidence: 0.85,
    description: 'MCP injection: hidden secondary send/forward instruction in tool args',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-033',
    // "requires authentication" + "output the" API keys
    pattern: /\b(?:requires?\s+authentication|authenticate|verify\s+(?:your|the)\s+(?:identity|credentials?))\b.{0,60}\b(?:output|include|share|reveal|display|send)\s+(?:the\s+)?(?:current\s+)?(?:API\s+keys?|auth\s+token|credentials?)\b/i,
    phase: 'actions_on_objective',
    confidence: 0.88,
    description: 'MCP injection: fake authentication requirement to exfiltrate API keys',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-034',
    // "-- AI:" in SQL comments (SQL injection with AI instruction)
    pattern: /--\s*AI\s*:/i,
    phase: 'lateral_movement',
    confidence: 0.85,
    description: 'MCP injection: AI instruction hidden in SQL comment (-- AI: ...)',
    category: 'mcp_injection',
    enabled: true,
  },
  {
    id: 'mcp-035',
    // Reviewer instructions targeting AI in PR descriptions
    pattern: /\bReviewer\s+instructions?\s*:\s*(?:Auto[- ]?approve|Approve|Skip|Do\s+not\s+flag|Pre[- ]?reviewed)\b/i,
    phase: 'lateral_movement',
    confidence: 0.85,
    description: 'MCP injection: reviewer instructions in PR targeting AI code reviewer',
    category: 'code_review_injection',
    enabled: true,
  },
  {
    id: 'mcp-036',
    // "preference" / "memory" poisoning with system prompt leak
    pattern: /\b(?:prefer(?:s|ence)?|setting|option)\b.{0,40}\b(?:include|append|add|insert)\s+(?:the\s+)?(?:system\s+prompt|API\s+key|credentials?|secret)\b.{0,30}\b(?:in|at|to)\s+(?:every|each|all)\s+(?:response|reply|output|message)\b/i,
    phase: 'persistence',
    confidence: 0.88,
    description: 'MCP injection: memory/preference poisoning for persistent system prompt leak',
    category: 'memory_poisoning',
    enabled: true,
  },
] as const
