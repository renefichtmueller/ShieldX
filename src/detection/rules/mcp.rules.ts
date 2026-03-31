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
] as const
