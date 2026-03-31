/**
 * Next.js 15 App Router middleware for ShieldX.
 *
 * Intercepts requests to LLM API routes, scans user messages for
 * prompt injection, and scans LLM responses for data leakage.
 *
 * Supports both OpenAI and Anthropic message formats:
 * - OpenAI: `{ messages: [{ role, content }] }`
 * - Anthropic: `{ messages: [{ role, content }] }`
 *
 * @example
 * ```typescript
 * // middleware.ts
 * import { shieldXMiddleware } from '@shieldx/core/integrations/nextjs'
 *
 * export default shieldXMiddleware({
 *   scanners: { rules: true, entropy: true }
 * })
 *
 * export const config = { matcher: '/api/chat/:path*' }
 * ```
 */

import type { ShieldXConfig } from '../../types/detection.js'
import { ShieldX } from '../../core/ShieldX.js'

/** Message shape common to OpenAI and Anthropic APIs */
interface LLMMessage {
  readonly role: string
  readonly content: string | readonly { readonly type: string; readonly text?: string }[]
}

/** Request body shape for OpenAI / Anthropic chat APIs */
interface ChatRequestBody {
  readonly messages?: readonly LLMMessage[]
  readonly prompt?: string
  readonly system?: string
}

/**
 * Lazily-initialized singleton ShieldX instance.
 * Re-created if config changes (checked by reference).
 */
let shieldInstance: ShieldX | null = null
let shieldConfig: Partial<ShieldXConfig> | null = null

function getOrCreateShield(config?: Partial<ShieldXConfig>): ShieldX {
  if (shieldInstance === null || config !== shieldConfig) {
    shieldConfig = config ?? null
    shieldInstance = new ShieldX(config)
  }
  return shieldInstance
}

/**
 * Extract the latest user message text from a chat request body.
 * Handles OpenAI `messages[]`, Anthropic `messages[]`, and raw `prompt`.
 */
function extractUserMessage(body: ChatRequestBody): string | null {
  // OpenAI / Anthropic messages array
  if (body.messages && body.messages.length > 0) {
    // Find the last user message
    for (let i = body.messages.length - 1; i >= 0; i--) {
      const msg = body.messages[i]
      if (msg === undefined) continue
      if (msg.role === 'user') {
        if (typeof msg.content === 'string') return msg.content
        // Anthropic multi-part content
        if (Array.isArray(msg.content)) {
          const textParts = msg.content
            .filter((p) => p.type === 'text' && typeof p.text === 'string')
            .map((p) => p.text ?? '')
          return textParts.join(' ') || null
        }
      }
    }
  }

  // Raw prompt field
  if (typeof body.prompt === 'string' && body.prompt.length > 0) {
    return body.prompt
  }

  return null
}

/**
 * Create a Next.js middleware function that scans LLM traffic.
 *
 * @param config - Optional ShieldX configuration overrides
 * @returns A Next.js middleware function
 */
export function shieldXMiddleware(config?: Partial<ShieldXConfig>) {
  const shield = getOrCreateShield(config)

  /**
   * Next.js middleware handler.
   * Compatible with Next.js 15 App Router middleware signature.
   */
  return async function middleware(
    request: Request,
  ): Promise<Response> {
    // Only intercept POST requests (chat/completion endpoints)
    if (request.method !== 'POST') {
      return fetch(request)
    }

    let body: ChatRequestBody
    try {
      body = await request.clone().json() as ChatRequestBody
    } catch {
      // Not JSON — pass through
      return fetch(request)
    }

    const userMessage = extractUserMessage(body)
    if (userMessage === null) {
      return fetch(request)
    }

    // Scan input
    const scanResult = await shield.scanInput(userMessage)

    // Block / Incident: return 400 with generic error
    if (scanResult.action === 'block' || scanResult.action === 'incident') {
      return new Response(
        JSON.stringify({
          error: 'Request blocked by security policy.',
          scanId: scanResult.id,
        }),
        {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            'X-ShieldX-Threat-Level': scanResult.threatLevel,
            'X-ShieldX-Action': scanResult.action,
            'X-ShieldX-Scan-Id': scanResult.id,
          },
        },
      )
    }

    // Sanitize: replace user message in body
    let modifiedRequest = request
    if (
      scanResult.action === 'sanitize' &&
      scanResult.sanitizedInput !== undefined
    ) {
      const modifiedBody = replaceUserMessage(body, scanResult.sanitizedInput)
      modifiedRequest = new Request(request.url, {
        method: request.method,
        headers: request.headers,
        body: JSON.stringify(modifiedBody),
      })
    }

    // Forward to upstream
    const response = await fetch(modifiedRequest)

    // Add ShieldX headers
    const headers = new Headers(response.headers)
    headers.set('X-ShieldX-Threat-Level', scanResult.threatLevel)
    headers.set('X-ShieldX-Action', scanResult.action)
    headers.set('X-ShieldX-Scan-Id', scanResult.id)

    // Scan output (non-streaming responses only)
    if (
      response.headers.get('content-type')?.includes('application/json')
    ) {
      try {
        const responseBody = await response.clone().json() as Record<string, unknown>
        const outputText = extractOutputText(responseBody)
        if (outputText !== null) {
          const outputScan = await shield.scanOutput(outputText)
          headers.set('X-ShieldX-Output-Threat-Level', outputScan.threatLevel)
          headers.set('X-ShieldX-Output-Action', outputScan.action)
        }
      } catch {
        // Failed to parse response — skip output scan
      }
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    })
  }
}

/**
 * HOC for individual API route handlers.
 * Wraps a handler with input/output scanning.
 *
 * @param handler - The original route handler function
 * @param config - Optional ShieldX configuration overrides
 * @returns Wrapped handler with ShieldX protection
 *
 * @example
 * ```typescript
 * import { withShieldX } from '@shieldx/core/integrations/nextjs'
 *
 * async function POST(request: Request) {
 *   // Your LLM logic here
 *   return Response.json({ message: 'Hello' })
 * }
 *
 * export const POST_HANDLER = withShieldX(POST)
 * ```
 */
export function withShieldX(
  handler: (request: Request) => Promise<Response>,
  config?: Partial<ShieldXConfig>,
): (request: Request) => Promise<Response> {
  const shield = getOrCreateShield(config)

  return async function shieldXHandler(request: Request): Promise<Response> {
    // Only scan POST bodies
    if (request.method !== 'POST') {
      return handler(request)
    }

    let body: ChatRequestBody
    try {
      body = await request.clone().json() as ChatRequestBody
    } catch {
      return handler(request)
    }

    const userMessage = extractUserMessage(body)
    if (userMessage === null) {
      return handler(request)
    }

    // Scan input
    const scanResult = await shield.scanInput(userMessage)

    if (scanResult.action === 'block' || scanResult.action === 'incident') {
      return new Response(
        JSON.stringify({
          error: 'Request blocked by security policy.',
          scanId: scanResult.id,
        }),
        {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            'X-ShieldX-Threat-Level': scanResult.threatLevel,
            'X-ShieldX-Action': scanResult.action,
            'X-ShieldX-Scan-Id': scanResult.id,
          },
        },
      )
    }

    // Sanitize the request if needed
    let processedRequest = request
    if (
      scanResult.action === 'sanitize' &&
      scanResult.sanitizedInput !== undefined
    ) {
      const modifiedBody = replaceUserMessage(body, scanResult.sanitizedInput)
      processedRequest = new Request(request.url, {
        method: request.method,
        headers: request.headers,
        body: JSON.stringify(modifiedBody),
      })
    }

    // Call the original handler
    const response = await handler(processedRequest)

    // Add ShieldX headers
    const headers = new Headers(response.headers)
    headers.set('X-ShieldX-Threat-Level', scanResult.threatLevel)
    headers.set('X-ShieldX-Action', scanResult.action)
    headers.set('X-ShieldX-Scan-Id', scanResult.id)

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    })
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Replace the last user message content in a chat request body.
 * Returns a new object — never mutates.
 */
function replaceUserMessage(
  body: ChatRequestBody,
  replacement: string,
): ChatRequestBody {
  if (!body.messages || body.messages.length === 0) {
    return { ...body, prompt: replacement }
  }

  const messages = [...body.messages]
  for (let i = messages.length - 1; i >= 0; i--) {
    const current = messages[i]
    if (current !== undefined && current.role === 'user') {
      messages[i] = { ...current, content: replacement }
      break
    }
  }

  return { ...body, messages }
}

/**
 * Extract output text from a JSON response body.
 * Supports OpenAI and Anthropic response formats.
 */
function extractOutputText(body: Record<string, unknown>): string | null {
  // OpenAI format: { choices: [{ message: { content } }] }
  if (Array.isArray(body.choices)) {
    const firstChoice = body.choices[0] as Record<string, unknown> | undefined
    if (firstChoice) {
      const message = firstChoice.message as Record<string, unknown> | undefined
      if (message && typeof message.content === 'string') {
        return message.content
      }
    }
  }

  // Anthropic format: { content: [{ text }] }
  if (Array.isArray(body.content)) {
    const texts = (body.content as Array<Record<string, unknown>>)
      .filter((c) => c.type === 'text' && typeof c.text === 'string')
      .map((c) => c.text as string)
    if (texts.length > 0) return texts.join(' ')
  }

  // Ollama format: { message: { content } } or { response }
  if (typeof body.response === 'string') return body.response
  const msg = body.message as Record<string, unknown> | undefined
  if (msg && typeof msg.content === 'string') return msg.content

  return null
}
