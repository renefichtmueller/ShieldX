/**
 * Anthropic SDK integration for ShieldX.
 *
 * Wraps the Anthropic Messages API with automatic
 * input/output scanning for prompt injection defense.
 *
 * @example
 * ```typescript
 * import { ShieldX } from '@shieldx/core'
 * import { createAnthropicClient } from '@shieldx/core/integrations/anthropic'
 *
 * const shield = new ShieldX()
 * const anthropic = createAnthropicClient({ apiKey: process.env.ANTHROPIC_API_KEY, shieldx: shield })
 * const result = await anthropic.createMessage({ model: 'claude-sonnet-4-20250514', max_tokens: 1024, messages: [...] })
 * ```
 */

export { createAnthropicClient } from './client.js'
export type { AnthropicClient, AnthropicMessageParams, AnthropicMessageResponse } from './client.js'
