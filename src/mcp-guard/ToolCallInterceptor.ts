/**
 * Tool Call Interceptor — pre/post hook system for tool calls.
 * Enables pluggable validation and sanitization around tool execution.
 * Part of ShieldX Layer 7 (MCP Guard & Tool Security).
 */

/** Result from a pre-execution hook */
interface PreHookResult {
  readonly proceed: boolean
  readonly modifiedArgs?: Readonly<Record<string, unknown>>
}

/** Result from a post-execution hook */
interface PostHookResult {
  readonly allow: boolean
  readonly sanitizedResult?: unknown
}

/** Result from the full intercept pipeline */
interface InterceptResult {
  readonly result: unknown
  readonly blocked: boolean
  readonly reason?: string
}

/** Pre-hook function signature */
type PreHook = (
  toolName: string,
  args: Readonly<Record<string, unknown>>,
) => Promise<PreHookResult>

/** Post-hook function signature */
type PostHook = (
  toolName: string,
  result: unknown,
) => Promise<PostHookResult>

/** Executor function signature */
type ToolExecutor = () => Promise<unknown>

/**
 * Immutable hook registry.
 * Each registration creates a new array rather than mutating.
 */
let preHooks: readonly PreHook[] = []
let postHooks: readonly PostHook[] = []

/**
 * Registers a pre-execution hook.
 * Pre-hooks run before tool execution and can block or modify arguments.
 *
 * @param hook - Function that receives tool name and args, returns proceed decision
 */
export function registerPreHook(hook: PreHook): void {
  preHooks = [...preHooks, hook]
}

/**
 * Registers a post-execution hook.
 * Post-hooks run after tool execution and can block or sanitize results.
 *
 * @param hook - Function that receives tool name and result, returns allow decision
 */
export function registerPostHook(hook: PostHook): void {
  postHooks = [...postHooks, hook]
}

/**
 * Runs all pre-hooks in registration order.
 * If any hook returns proceed=false, execution is blocked.
 * Args may be modified by hooks (each hook sees the args from the previous one).
 */
async function runPreHooks(
  toolName: string,
  args: Readonly<Record<string, unknown>>,
): Promise<{ readonly proceed: boolean; readonly finalArgs: Readonly<Record<string, unknown>>; readonly blockReason?: string }> {
  let currentArgs = args

  for (const hook of preHooks) {
    const hookResult = await hook(toolName, currentArgs)

    if (!hookResult.proceed) {
      return {
        proceed: false,
        finalArgs: currentArgs,
        blockReason: `Pre-hook blocked execution of "${toolName}"`,
      }
    }

    if (hookResult.modifiedArgs !== undefined) {
      currentArgs = hookResult.modifiedArgs
    }
  }

  return { proceed: true, finalArgs: currentArgs }
}

/**
 * Runs all post-hooks in registration order.
 * If any hook returns allow=false, the result is blocked or sanitized.
 */
async function runPostHooks(
  toolName: string,
  result: unknown,
): Promise<{ readonly allowed: boolean; readonly finalResult: unknown; readonly blockReason?: string }> {
  let currentResult = result

  for (const hook of postHooks) {
    const hookResult = await hook(toolName, currentResult)

    if (!hookResult.allow) {
      if (hookResult.sanitizedResult !== undefined) {
        return {
          allowed: true,
          finalResult: hookResult.sanitizedResult,
        }
      }
      return {
        allowed: false,
        finalResult: undefined,
        blockReason: `Post-hook blocked result from "${toolName}"`,
      }
    }

    if (hookResult.sanitizedResult !== undefined) {
      currentResult = hookResult.sanitizedResult
    }
  }

  return { allowed: true, finalResult: currentResult }
}

/**
 * Intercepts a tool call with pre/post hooks around execution.
 *
 * Flow:
 * 1. Run all pre-hooks. If any blocks, return immediately.
 * 2. Execute the tool via the provided executor.
 * 3. Run all post-hooks on the result. If any blocks, sanitize or block.
 *
 * @param toolName - Name of the tool being called
 * @param args - Arguments being passed to the tool
 * @param executor - Function that actually executes the tool
 * @returns The tool result, or a blocked indicator with reason
 */
export async function intercept(
  toolName: string,
  args: Readonly<Record<string, unknown>>,
  executor: ToolExecutor,
): Promise<InterceptResult> {
  // Run pre-hooks
  const preResult = await runPreHooks(toolName, args)
  if (!preResult.proceed) {
    const base = { result: undefined, blocked: true as const }
    return preResult.blockReason !== undefined
      ? { ...base, reason: preResult.blockReason }
      : base
  }

  // Execute the tool
  let executionResult: unknown
  try {
    executionResult = await executor()
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error during tool execution'
    return {
      result: undefined,
      blocked: true,
      reason: `Tool execution failed: ${message}`,
    }
  }

  // Run post-hooks
  const postResult = await runPostHooks(toolName, executionResult)
  if (!postResult.allowed) {
    const base = { result: undefined, blocked: true as const }
    return postResult.blockReason !== undefined
      ? { ...base, reason: postResult.blockReason }
      : base
  }

  return {
    result: postResult.finalResult,
    blocked: false,
  }
}

/**
 * Clears all registered hooks.
 * Useful for testing and session cleanup.
 */
export function clearHooks(): void {
  preHooks = []
  postHooks = []
}

/**
 * Returns the current count of registered hooks (for diagnostics).
 */
export function hookCount(): { readonly pre: number; readonly post: number } {
  return { pre: preHooks.length, post: postHooks.length }
}
