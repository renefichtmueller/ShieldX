/**
 * ShieldX Drop-In Middleware for EO Global Pulse
 *
 * Copy this file to: eo-global-pulse/src/lib/shieldx-middleware.ts
 * Then import in your AI routes:
 *
 *   import { scanWithShieldX } from '@/lib/shieldx-middleware'
 *   const scanResult = await scanWithShieldX(userMessage)
 *   if (scanResult.blocked) return scanResult.response
 *
 * When the ShieldX proxy is running on :11435, configure OLLAMA_URL
 * to point there instead of :11434 — all Ollama calls are then protected.
 *
 * This middleware provides ADDITIONAL protection for the chat route
 * beyond what the proxy does, adding request-level context.
 */

import { NextResponse } from 'next/server'

const SHIELDX_PROXY = process.env.SHIELDX_PROXY_URL || 'http://localhost:11435'
const SHIELDX_ENABLED = process.env.SHIELDX_ENABLED !== 'false'

interface ShieldXScanResult {
  blocked: boolean
  threatLevel: string
  killChainPhase: string
  action: string
  matchedPatterns: string[]
  latencyMs: number
  response?: NextResponse
}

/**
 * Scan user input with ShieldX before processing.
 * Falls back gracefully if ShieldX proxy is unavailable.
 */
export async function scanWithShieldX(input: string): Promise<ShieldXScanResult> {
  if (!SHIELDX_ENABLED) {
    return { blocked: false, threatLevel: 'none', killChainPhase: 'none', action: 'allow', matchedPatterns: [], latencyMs: 0 }
  }

  try {
    const start = Date.now()
    const res = await fetch(`${SHIELDX_PROXY}/shieldx/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input }),
      signal: AbortSignal.timeout(5000),
    })

    if (!res.ok) {
      // ShieldX unavailable — fail open (allow request)
      console.warn('[ShieldX] Proxy unavailable, failing open')
      return { blocked: false, threatLevel: 'unknown', killChainPhase: 'none', action: 'allow', matchedPatterns: [], latencyMs: Date.now() - start }
    }

    const result = await res.json()
    const latencyMs = Date.now() - start

    if (result.action === 'block' || result.action === 'incident') {
      return {
        blocked: true,
        threatLevel: result.threatLevel,
        killChainPhase: result.killChainPhase,
        action: result.action,
        matchedPatterns: result.matchedPatterns || [],
        latencyMs,
        response: NextResponse.json(
          { error: 'Request blocked by security filter', threatLevel: result.threatLevel },
          { status: 403 }
        ),
      }
    }

    return {
      blocked: false,
      threatLevel: result.threatLevel || 'none',
      killChainPhase: result.killChainPhase || 'none',
      action: result.action || 'allow',
      matchedPatterns: result.matchedPatterns || [],
      latencyMs,
    }
  } catch {
    // Network error — fail open
    console.warn('[ShieldX] Scan failed, failing open')
    return { blocked: false, threatLevel: 'unknown', killChainPhase: 'none', action: 'allow', matchedPatterns: [], latencyMs: 0 }
  }
}

/**
 * Wrapper: Change OLLAMA_URL to point through ShieldX proxy.
 * Add this to your .env.local:
 *   OLLAMA_URL=http://localhost:11435
 *
 * This is the SIMPLEST integration — just change the Ollama URL.
 * The proxy scans everything transparently.
 */
export function getProtectedOllamaUrl(): string {
  return process.env.OLLAMA_URL || SHIELDX_PROXY
}
