/**
 * Ollama client with ShieldX protection.
 *
 * Uses native `fetch` (Node.js 20+). Scans all user messages before
 * sending to Ollama and scans responses before returning to the caller.
 *
 * Supports both `chat` (multi-turn) and `generate` (single prompt) endpoints.
 * The `embeddings` endpoint bypasses ShieldX since embeddings are not user-facing.
 */

import type { ShieldXResult } from '../../types/detection.js'
import type { ShieldX } from '../../core/ShieldX.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Ollama chat message */
export interface OllamaMessage {
  readonly role: string
  readonly content: string
}

/** Parameters for ollama.chat() */
export interface OllamaChatParams {
  readonly messages: readonly OllamaMessage[]
  readonly model?: string
  readonly stream?: boolean
  readonly options?: Readonly<Record<string, unknown>>
}

/** Response from ollama.chat() */
export interface OllamaChatResponse {
  readonly message: OllamaMessage
  readonly model: string
  readonly done: boolean
  readonly total_duration?: number
  readonly shieldx?: ShieldXResult
}

/** Parameters for ollama.generate() */
export interface OllamaGenerateParams {
  readonly prompt: string
  readonly model?: string
  readonly stream?: boolean
  readonly system?: string
  readonly options?: Readonly<Record<string, unknown>>
}

/** Response from ollama.generate() */
export interface OllamaGenerateResponse {
  readonly response: string
  readonly model: string
  readonly done: boolean
  readonly total_duration?: number
  readonly shieldx?: ShieldXResult
}

/** Parameters for ollama.embeddings() */
export interface OllamaEmbeddingsParams {
  readonly prompt: string
  readonly model?: string
}

/** Response from ollama.embeddings() */
export interface OllamaEmbeddingsResponse {
  readonly embedding: readonly number[]
}

/** Ollama client options */
export interface OllamaClientOptions {
  readonly endpoint?: string
  readonly model?: string
  readonly shieldx?: ShieldX
}

/** Ollama client interface */
export interface OllamaClient {
  /**
   * Multi-turn chat completion with ShieldX protection.
   * Scans the last user message before sending, scans response after.
   */
  chat(params: OllamaChatParams): Promise<OllamaChatResponse>

  /**
   * Single prompt generation with ShieldX protection.
   * Scans prompt before sending, scans response after.
   */
  generate(params: OllamaGenerateParams): Promise<OllamaGenerateResponse>

  /**
   * Generate embeddings. Bypasses ShieldX — embeddings are not user-facing.
   */
  embeddings(params: OllamaEmbeddingsParams): Promise<OllamaEmbeddingsResponse>
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

const DEFAULT_ENDPOINT = 'http://localhost:11434'
const DEFAULT_MODEL = 'llama3.2'

/**
 * Create a ShieldX-protected Ollama client.
 *
 * @param options - Endpoint, default model, and optional ShieldX instance
 * @returns An OllamaClient with automatic input/output scanning
 */
export function createOllamaClient(options: OllamaClientOptions = {}): OllamaClient {
  const endpoint = (options.endpoint ?? DEFAULT_ENDPOINT).replace(/\/$/, '')
  const defaultModel = options.model ?? DEFAULT_MODEL
  const shield = options.shieldx ?? null

  /**
   * Extract the last user message from a messages array.
   */
  function extractLastUserMessage(messages: readonly OllamaMessage[]): string | null {
    for (let i = messages.length - 1; i >= 0; i--) {
      const msg = messages[i]
      if (msg !== undefined && msg.role === 'user') {
        return msg.content
      }
    }
    return null
  }

  return {
    async chat(params: OllamaChatParams): Promise<OllamaChatResponse> {
      const model = params.model ?? defaultModel
      let shieldxResult: ShieldXResult | undefined

      // Scan input
      if (shield !== null) {
        const userMessage = extractLastUserMessage(params.messages)
        if (userMessage !== null) {
          const scanResult = await shield.scanInput(userMessage)
          shieldxResult = scanResult

          if (scanResult.action === 'block' || scanResult.action === 'incident') {
            return {
              message: { role: 'assistant', content: 'Request blocked by security policy.' },
              model,
              done: true,
              shieldx: scanResult,
            }
          }
        }
      }

      // Call Ollama
      const response = await fetch(`${endpoint}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model,
          messages: params.messages,
          stream: false,
          ...(params.options !== undefined ? { options: params.options } : {}),
        }),
      })

      if (!response.ok) {
        throw new Error(`Ollama chat failed: ${response.status} ${response.statusText}`)
      }

      const data = await response.json() as OllamaChatResponse

      // Scan output
      if (shield !== null && data.message?.content) {
        const outputScan = await shield.scanOutput(data.message.content)
        if (outputScan.detected) {
          shieldxResult = outputScan
          if (outputScan.action === 'block' || outputScan.action === 'incident') {
            return {
              ...data,
              message: { role: 'assistant', content: 'Response filtered by security policy.' },
              shieldx: outputScan,
            }
          }
        }
      }

      return {
        ...data,
        ...(shieldxResult !== undefined ? { shieldx: shieldxResult } : {}),
      }
    },

    async generate(params: OllamaGenerateParams): Promise<OllamaGenerateResponse> {
      const model = params.model ?? defaultModel
      let shieldxResult: ShieldXResult | undefined

      // Scan input
      if (shield !== null) {
        const scanResult = await shield.scanInput(params.prompt)
        shieldxResult = scanResult

        if (scanResult.action === 'block' || scanResult.action === 'incident') {
          return {
            response: 'Request blocked by security policy.',
            model,
            done: true,
            shieldx: scanResult,
          }
        }
      }

      // Call Ollama
      const response = await fetch(`${endpoint}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model,
          prompt: params.prompt,
          stream: false,
          ...(params.system !== undefined ? { system: params.system } : {}),
          ...(params.options !== undefined ? { options: params.options } : {}),
        }),
      })

      if (!response.ok) {
        throw new Error(`Ollama generate failed: ${response.status} ${response.statusText}`)
      }

      const data = await response.json() as OllamaGenerateResponse

      // Scan output
      if (shield !== null && data.response) {
        const outputScan = await shield.scanOutput(data.response)
        if (outputScan.detected) {
          shieldxResult = outputScan
          if (outputScan.action === 'block' || outputScan.action === 'incident') {
            return {
              ...data,
              response: 'Response filtered by security policy.',
              shieldx: outputScan,
            }
          }
        }
      }

      return {
        ...data,
        ...(shieldxResult !== undefined ? { shieldx: shieldxResult } : {}),
      }
    },

    async embeddings(params: OllamaEmbeddingsParams): Promise<OllamaEmbeddingsResponse> {
      const model = params.model ?? defaultModel

      const response = await fetch(`${endpoint}/api/embeddings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, prompt: params.prompt }),
      })

      if (!response.ok) {
        throw new Error(`Ollama embeddings failed: ${response.status} ${response.statusText}`)
      }

      return response.json() as Promise<OllamaEmbeddingsResponse>
    },
  }
}
