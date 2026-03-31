/**
 * MCP (Model Context Protocol) tool poisoning patterns.
 * Detects attempts to inject malicious instructions via tool descriptions,
 * metadata, or response manipulation in MCP tool calls.
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
] as const
