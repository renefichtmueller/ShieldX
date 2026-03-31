/**
 * MCP Guard & Tool Security — Layer 7 of the ShieldX defense pipeline.
 *
 * Provides comprehensive protection for MCP tool ecosystems:
 * - Tool definition inspection and poison detection
 * - Least-privilege enforcement for tool calls
 * - Pre/post hook interception system
 * - Ollama-specific request validation
 * - Decision dependency graph analysis (MindGuard-inspired)
 * - RSA-signed manifest verification
 * - Tool chain sequence monitoring
 * - Resource governance and DoS/DoW prevention
 */

export {
  inspectTool,
  inspectAllTools,
  validateCall,
} from './MCPInspector.js'

export {
  detect as detectToolPoison,
  checkParameterName,
  checkSchemaParameters,
} from './ToolPoisonDetector.js'

export {
  setAllowedTools,
  setSensitiveResources,
  checkPrivilege,
  clearSession as clearPrivilegeSession,
  getSessionPrivileges,
} from './PrivilegeChecker.js'

export {
  registerPreHook,
  registerPostHook,
  intercept,
  clearHooks,
  hookCount,
} from './ToolCallInterceptor.js'

export {
  validateRequest as validateOllamaRequest,
} from './OllamaGuard.js'

export {
  buildGraph as buildDecisionGraph,
  analyzeGraph as analyzeDecisionGraph,
} from './DecisionGraphAnalyzer.js'

export {
  generateManifest,
  signManifest,
  verifyManifest,
  compareManifest,
  hashManifest,
} from './ManifestVerifier.js'

export {
  recordCall as recordToolCall,
  analyzeSequence as analyzeToolSequence,
  clearSession as clearToolChainSession,
  getWindowSize as getToolChainWindowSize,
} from './ToolChainGuard.js'

export {
  checkBudget,
  recordUsage,
  getUsage,
  setLimits,
  setPricing,
  clearSession as clearResourceSession,
} from './ResourceGovernor.js'
