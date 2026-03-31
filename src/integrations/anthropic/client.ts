/**
 * Anthropic Messages API client with ShieldX protection.
 *
 * Uses native `fetch` (Node.js 20+) to call the Anthropic API directly.
 * Scans all user messages before the API call and scans the response after.
 *
 * Does NOT depend on the `@anthropic-ai/sdk` package — uses the raw HTTP API
 * so ShieldX has zero external dependencies beyond Node.js built-ins.
 */

import type { ShieldXResult } from '../../types/detection.js'
import type { ShieldX } from '../../core/ShieldX.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Anthropic message content block */
export interface AnthropicContentBlock {
  readonly type: 'text' | 'image' | 'tool_use' | 'tool_result'
  readonly text?: string
  readonly [key: string]: unknown
}

/** Anthropic message */
export interface AnthropicMessage {
  readonly role: 'user' | 'assistant'
  readonly content: string | readonly AnthropicContentBlock[]
}

/** Parameters for createMessage() */
export interface AnthropicMessageParams {
  readonly model: string
  readonly max_tokens: number
  readonly messages: readonly AnthropicMessage[]
  readonly system?: string
  readonly temperature?: number
  readonly top_p?: number
  readonly top_k?: number
  readonly stop_sequences?: readonly string[]
  readonly metadata?: Readonly<Record<string, unknown>>
}

/** Response from createMessage() */
export interface AnthropicMessageResponse {
  readonly id: string
  readonly type: 'message'
  readonly role: 'assistant'
  readonly content: readonly AnthropicContentBlock[]
  readonly model: string
  readonly stop_reason: string | null
  readonly usage: {
    readonly input_tokens: number
    readonly output_tokens: number
  }
  readonly shieldx?: ShieldXResult
}

/** Anthropic client options */
export interface AnthropicClientOptions {
  readonly apiKey?: string
  readonly baseUrl?: string
  readonly shieldx?: ShieldX
}

/** Anthropic client interface */
export interface AnthropicClient {
  /**
   * Create a message with ShieldX protection.
   * Scans all user messages before the API call, scans the response after.
   */
  createMessage(params: AnthropicMessageParams): Promise<AnthropicMessageResponse>
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

const DEFAULT_BASE_URL = 'https://api.anthropic.com'
const API_VERSION = '2023-06-01'

/**
 * Create a ShieldX-protected Anthropic client.
 *
 * @param options - API key, optional base URL, and optional ShieldX instance
 * @returns An AnthropicClient with automatic input/output scanning
 */
export function createAnthropicClient(options: AnthropicClientOptions = {}): AnthropicClient {
  const apiKey = options.apiKey ?? process.env.ANTHROPIC_API_KEY ?? ''
  const baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, '')
  const shield = options.shieldx ?? null

  if (apiKey.length === 0) {
    throw new Error(
      'Anthropic API key required. Pass via options.apiKey or set ANTHROPIC_API_KEY environment variable.',
    )
  }

  /**
   * Extract all user message text from a messages array.
   */
  function extractUserMessages(messages: readonly AnthropicMessage[]): string {
    const parts: string[] = []
    for (const msg of messages) {
      if (msg.role === 'user') {
        if (typeof msg.content === 'string') {
          parts.push(msg.content)
        } else if (Array.isArray(msg.content)) {
          for (const block of msg.content) {
            if (block.type === 'text' && typeof block.text === 'string') {
              parts.push(block.text)
            }
          }
        }
      }
    }
    return parts.join(' ')
  }

  /**
   * Extract text from response content blocks.
   */
  function extractResponseText(content: readonly AnthropicContentBlock[]): string {
    return content
      .filter((block) => block.type === 'text' && typeof block.text === 'string')
      .map((block) => block.text ?? '')
      .join(' ')
  }

  return {
    async createMessage(params: AnthropicMessageParams): Promise<AnthropicMessageResponse> {
      let shieldxResult: ShieldXResult | undefined

      // Scan input messages
      if (shield !== null) {
        const userText = extractUserMessages(params.messages)
        if (userText.length > 0) {
          const scanResult = await shield.scanInput(userText)
          shieldxResult = scanResult

          if (scanResult.action === 'block' || scanResult.action === 'incident') {
            return {
              id: `msg_shieldx_blocked_${Date.now()}`,
              type: 'message',
              role: 'assistant',
              content: [{ type: 'text', text: 'Request blocked by security policy.' }],
              model: params.model,
              stop_reason: 'end_turn',
              usage: { input_tokens: 0, output_tokens: 0 },
              shieldx: scanResult,
            }
          }
        }

        // Also scan system prompt if present
        if (params.system !== undefined && params.system.length > 0) {
          // System prompt scanning is informational — don't block
          await shield.scanInput(params.system)
        }
      }

      // Call Anthropic API
      const response = await fetch(`${baseUrl}/v1/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': API_VERSION,
        },
        body: JSON.stringify({
          model: params.model,
          max_tokens: params.max_tokens,
          messages: params.messages,
          ...(params.system !== undefined ? { system: params.system } : {}),
          ...(params.temperature !== undefined ? { temperature: params.temperature } : {}),
          ...(params.top_p !== undefined ? { top_p: params.top_p } : {}),
          ...(params.top_k !== undefined ? { top_k: params.top_k } : {}),
          ...(params.stop_sequences !== undefined ? { stop_sequences: params.stop_sequences } : {}),
          ...(params.metadata !== undefined ? { metadata: params.metadata } : {}),
        }),
      })

      if (!response.ok) {
        const errorBody = await response.text()
        throw new Error(`Anthropic API error: ${response.status} ${response.statusText} — ${errorBody}`)
      }

      const data = await response.json() as AnthropicMessageResponse

      // Scan output
      if (shield !== null && data.content.length > 0) {
        const responseText = extractResponseText(data.content)
        if (responseText.length > 0) {
          const outputScan = await shield.scanOutput(responseText)
          if (outputScan.detected) {
            shieldxResult = outputScan
            if (outputScan.action === 'block' || outputScan.action === 'incident') {
              return {
                ...data,
                content: [{ type: 'text', text: 'Response filtered by security policy.' }],
                shieldx: outputScan,
              }
            }
          }
        }
      }

      return {
        ...data,
        ...(shieldxResult !== undefined ? { shieldx: shieldxResult } : {}),
      }
    },
  }
}
