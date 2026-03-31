/**
 * Ollama integration for ShieldX.
 *
 * Thin wrapper around the Ollama HTTP API that automatically
 * scans input and output for prompt injection attacks.
 *
 * @example
 * ```typescript
 * import { ShieldX } from '@shieldx/core'
 * import { createOllamaClient } from '@shieldx/core/integrations/ollama'
 *
 * const shield = new ShieldX()
 * const ollama = createOllamaClient({ shieldx: shield })
 * const result = await ollama.chat({ messages: [{ role: 'user', content: 'Hello' }] })
 * ```
 */

export { createOllamaClient } from './client.js'
export type { OllamaClient, OllamaChatParams, OllamaChatResponse, OllamaGenerateParams, OllamaGenerateResponse } from './client.js'
