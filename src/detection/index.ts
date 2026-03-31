/**
 * Detection module — Layer 1 of the ShieldX defense pipeline.
 * Exports the RuleEngine and all rule definitions.
 */

export { RuleEngine } from './RuleEngine'
export type { InjectionRule } from './rules/base.rules'

export { rules as baseRules } from './rules/base.rules'
export { rules as jailbreakRules } from './rules/jailbreak.rules'
export { rules as extractionRules } from './rules/extraction.rules'
export { rules as delimiterRules } from './rules/delimiter.rules'
export { rules as encodingRules } from './rules/encoding.rules'
export { rules as persistenceRules } from './rules/persistence.rules'
export { rules as exfiltrationRules } from './rules/exfiltration.rules'
export { rules as mcpRules } from './rules/mcp.rules'
export { rules as multilingualRules } from './rules/multilingual.rules'
