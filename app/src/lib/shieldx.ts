'use client'

/**
 * ShieldX browser-compatible scanner.
 *
 * The core ShieldX class uses Node.js APIs (node:crypto, pino) that cannot
 * run in the browser. This module provides a self-contained client-side
 * scanner that replicates the rule-based detection layer (L1) with a
 * curated set of injection patterns. It produces the same ShieldXResult
 * shape so the dashboard works identically.
 */

// ---------------------------------------------------------------------------
// Types (mirrored from src/types/detection.ts for browser use)
// ---------------------------------------------------------------------------

export type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type KillChainPhase =
  | 'none'
  | 'initial_access'
  | 'privilege_escalation'
  | 'reconnaissance'
  | 'persistence'
  | 'command_and_control'
  | 'lateral_movement'
  | 'actions_on_objective'

export type HealingAction = 'allow' | 'sanitize' | 'warn' | 'block' | 'reset' | 'incident'

export interface ScanResult {
  readonly scannerId: string
  readonly scannerType: string
  readonly detected: boolean
  readonly confidence: number
  readonly threatLevel: ThreatLevel
  readonly killChainPhase: KillChainPhase
  readonly matchedPatterns: readonly string[]
  readonly latencyMs: number
}

export interface ShieldXResult {
  readonly id: string
  readonly timestamp: string
  readonly input: string
  readonly sanitizedInput?: string
  readonly detected: boolean
  readonly threatLevel: ThreatLevel
  readonly killChainPhase: KillChainPhase
  readonly action: HealingAction
  readonly scanResults: readonly ScanResult[]
  readonly healingApplied: boolean
  readonly latencyMs: number
}

// ---------------------------------------------------------------------------
// Pattern database (curated subset)
// ---------------------------------------------------------------------------

interface AttackPattern {
  readonly id: string
  readonly regex: RegExp
  readonly name: string
  readonly phase: KillChainPhase
  readonly threat: ThreatLevel
  readonly confidence: number
}

const ATTACK_PATTERNS: readonly AttackPattern[] = [
  // Initial Access — instruction override
  { id: 'IA-001', regex: /ignore\s+(all\s+)?previous\s+(instructions?|prompts?|rules?)/i, name: 'Instruction override', phase: 'initial_access', threat: 'critical', confidence: 0.95 },
  { id: 'IA-002', regex: /forget\s+(all\s+|everything\s+)?(you\s+)?know/i, name: 'Memory wipe attempt', phase: 'initial_access', threat: 'high', confidence: 0.9 },
  { id: 'IA-003', regex: /disregard\s+(your\s+)?(system\s+)?(prompt|instructions|rules)/i, name: 'Disregard directive', phase: 'initial_access', threat: 'critical', confidence: 0.95 },
  { id: 'IA-004', regex: /new\s+instructions?\s*:/i, name: 'New instructions injection', phase: 'initial_access', threat: 'high', confidence: 0.85 },
  { id: 'IA-005', regex: /you\s+are\s+now\s+/i, name: 'Role reassignment', phase: 'initial_access', threat: 'critical', confidence: 0.92 },
  { id: 'IA-006', regex: /act\s+as\s+(if\s+)?(you\s+)?(are|were)\s+/i, name: 'Role impersonation', phase: 'initial_access', threat: 'high', confidence: 0.85 },

  // Privilege Escalation
  { id: 'PE-001', regex: /\bDAN\b.*\bmode\b|\bDAN\b/i, name: 'DAN jailbreak', phase: 'privilege_escalation', threat: 'critical', confidence: 0.93 },
  { id: 'PE-002', regex: /developer\s+mode|god\s+mode|admin\s+mode/i, name: 'Privilege mode request', phase: 'privilege_escalation', threat: 'critical', confidence: 0.92 },
  { id: 'PE-003', regex: /no\s+(restrictions?|limits?|filters?|guardrails?|censorship)/i, name: 'Restriction removal', phase: 'privilege_escalation', threat: 'high', confidence: 0.88 },
  { id: 'PE-004', regex: /unlock\s+(all\s+)?capabilities/i, name: 'Capability unlock', phase: 'privilege_escalation', threat: 'high', confidence: 0.85 },
  { id: 'PE-005', regex: /jailbreak|jail\s*break/i, name: 'Jailbreak keyword', phase: 'privilege_escalation', threat: 'critical', confidence: 0.9 },

  // Reconnaissance
  { id: 'RC-001', regex: /print\s+(your\s+)?(system\s+)?prompt/i, name: 'System prompt extraction', phase: 'reconnaissance', threat: 'high', confidence: 0.9 },
  { id: 'RC-002', regex: /what\s+(are|is)\s+your\s+(system\s+)?(instructions?|rules?|prompt)/i, name: 'Instruction probing', phase: 'reconnaissance', threat: 'medium', confidence: 0.75 },
  { id: 'RC-003', regex: /reveal\s+(your\s+)?(system|hidden|secret|internal)/i, name: 'System reveal attempt', phase: 'reconnaissance', threat: 'high', confidence: 0.85 },
  { id: 'RC-004', regex: /show\s+me\s+(your\s+)?(config|configuration|settings|prompt)/i, name: 'Config extraction', phase: 'reconnaissance', threat: 'medium', confidence: 0.7 },

  // Persistence
  { id: 'PS-001', regex: /from\s+now\s+on\s*(,\s*)?you\s+(will|must|should|shall)/i, name: 'Persistent behavior change', phase: 'persistence', threat: 'high', confidence: 0.88 },
  { id: 'PS-002', regex: /always\s+remember\s+that/i, name: 'Memory injection', phase: 'persistence', threat: 'medium', confidence: 0.75 },
  { id: 'PS-003', regex: /for\s+all\s+future\s+(responses?|conversations?|messages?)/i, name: 'Future behavior override', phase: 'persistence', threat: 'high', confidence: 0.85 },

  // Command & Control
  { id: 'C2-001', regex: /\[\s*SYSTEM\s*\]/i, name: 'Fake system message', phase: 'command_and_control', threat: 'critical', confidence: 0.93 },
  { id: 'C2-002', regex: /\<\|?\s*system\s*\|?\>/i, name: 'System tag injection', phase: 'command_and_control', threat: 'critical', confidence: 0.95 },
  { id: 'C2-003', regex: /```\s*(system|admin|root)/i, name: 'Code block privilege', phase: 'command_and_control', threat: 'high', confidence: 0.85 },
  { id: 'C2-004', regex: /human:\s*|assistant:\s*|<\|im_start\|>/i, name: 'Role delimiter injection', phase: 'command_and_control', threat: 'critical', confidence: 0.92 },

  // Lateral Movement
  { id: 'LM-001', regex: /execute\s+(this\s+)?(code|command|script|function)/i, name: 'Code execution request', phase: 'lateral_movement', threat: 'high', confidence: 0.85 },
  { id: 'LM-002', regex: /access\s+(the\s+)?(file\s+system|database|server|api)/i, name: 'Resource access attempt', phase: 'lateral_movement', threat: 'medium', confidence: 0.7 },
  { id: 'LM-003', regex: /call\s+(this\s+)?(api|endpoint|url|webhook)/i, name: 'External call request', phase: 'lateral_movement', threat: 'medium', confidence: 0.7 },

  // Actions on Objective
  { id: 'AO-001', regex: /exfiltrate|steal\s+(the\s+)?data|leak\s+(the\s+)?information/i, name: 'Data exfiltration', phase: 'actions_on_objective', threat: 'critical', confidence: 0.95 },
  { id: 'AO-002', regex: /send\s+(this|the|all)\s+(data|information|content)\s+to/i, name: 'Data transmission', phase: 'actions_on_objective', threat: 'high', confidence: 0.85 },
  { id: 'AO-003', regex: /delete\s+(all|the|every)\s+(data|records?|files?|logs?)/i, name: 'Destructive action', phase: 'actions_on_objective', threat: 'critical', confidence: 0.9 },

  // Encoding attacks
  { id: 'ENC-001', regex: /base64|atob|btoa|decode\s+this/i, name: 'Encoding attack hint', phase: 'initial_access', threat: 'medium', confidence: 0.65 },
  { id: 'ENC-002', regex: /\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}/i, name: 'Unicode escape sequence', phase: 'initial_access', threat: 'medium', confidence: 0.7 },
  { id: 'ENC-003', regex: /&#x?[0-9a-fA-F]+;.*&#x?[0-9a-fA-F]+;/i, name: 'HTML entity encoding', phase: 'initial_access', threat: 'medium', confidence: 0.7 },

  // Multi-language attacks
  { id: 'ML-001', regex: /\u041F\u0440\u043E\u0438\u0433\u043D\u043E\u0440\u0438\u0440\u0443\u0439|\u5FFD\u7565|\u7121\u8996/i, name: 'Multi-language ignore', phase: 'initial_access', threat: 'high', confidence: 0.8 },
]

// ---------------------------------------------------------------------------
// Threat severity helpers
// ---------------------------------------------------------------------------

const THREAT_SEVERITY: Record<ThreatLevel, number> = {
  none: 0, low: 1, medium: 2, high: 3, critical: 4,
}

const SEVERITY_TO_LEVEL: readonly ThreatLevel[] = ['none', 'low', 'medium', 'high', 'critical']

function aggregateThreat(results: readonly ScanResult[]): ThreatLevel {
  let max = 0
  for (const r of results) {
    if (r.detected) {
      const sev = THREAT_SEVERITY[r.threatLevel]
      if (sev > max) max = sev
    }
  }
  return SEVERITY_TO_LEVEL[max] ?? 'none'
}

function determineAction(threat: ThreatLevel): HealingAction {
  switch (threat) {
    case 'none': return 'allow'
    case 'low': return 'warn'
    case 'medium': return 'sanitize'
    case 'high': return 'block'
    case 'critical': return 'block'
  }
}

// ---------------------------------------------------------------------------
// Browser-compatible ShieldX scanner
// ---------------------------------------------------------------------------

let idCounter = 0
function generateId(): string {
  idCounter += 1
  return `scan-${Date.now()}-${idCounter}`
}

export class ShieldXClient {
  private readonly scanHistory: ShieldXResult[] = []

  async scanInput(input: string): Promise<ShieldXResult> {
    const start = performance.now()
    const scanResults: ScanResult[] = []

    // Run all pattern checks
    for (const pattern of ATTACK_PATTERNS) {
      const match = pattern.regex.test(input)
      if (match) {
        scanResults.push({
          scannerId: `rule-${pattern.id}`,
          scannerType: 'rule',
          detected: true,
          confidence: pattern.confidence,
          threatLevel: pattern.threat,
          killChainPhase: pattern.phase,
          matchedPatterns: [pattern.name],
          latencyMs: performance.now() - start,
        })
      }
    }

    // Unicode analysis (check for suspicious chars)
    const unicodeResult = this.scanUnicode(input, start)
    scanResults.push(unicodeResult)

    // Entropy check
    const entropyResult = this.scanEntropy(input, start)
    scanResults.push(entropyResult)

    const detected = scanResults.some((r) => r.detected)
    const threatLevel = aggregateThreat(scanResults)
    const action = determineAction(threatLevel)

    // Determine primary kill chain phase
    const phaseVotes: Partial<Record<KillChainPhase, number>> = {}
    for (const r of scanResults) {
      if (r.detected && r.killChainPhase !== 'none') {
        phaseVotes[r.killChainPhase] = (phaseVotes[r.killChainPhase] ?? 0) + 1
      }
    }
    let primaryPhase: KillChainPhase = 'none'
    let maxVotes = 0
    for (const [phase, votes] of Object.entries(phaseVotes)) {
      if (votes > maxVotes) {
        maxVotes = votes
        primaryPhase = phase as KillChainPhase
      }
    }

    const result: ShieldXResult = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      input,
      detected,
      threatLevel,
      killChainPhase: primaryPhase,
      action,
      scanResults,
      healingApplied: action !== 'allow',
      latencyMs: performance.now() - start,
    }

    this.scanHistory.push(result)
    if (this.scanHistory.length > 1000) {
      this.scanHistory.splice(0, this.scanHistory.length - 1000)
    }

    return result
  }

  getHistory(): readonly ShieldXResult[] {
    return this.scanHistory
  }

  getStats() {
    const total = this.scanHistory.length
    const threats = this.scanHistory.filter((r) => r.detected).length
    const phaseMap: Partial<Record<KillChainPhase, number>> = {}
    for (const r of this.scanHistory) {
      if (r.detected) {
        phaseMap[r.killChainPhase] = (phaseMap[r.killChainPhase] ?? 0) + 1
      }
    }
    const avgLatency = total > 0
      ? this.scanHistory.reduce((sum, r) => sum + r.latencyMs, 0) / total
      : 0

    return { total, threats, phaseMap, avgLatency }
  }

  private scanUnicode(input: string, start: number): ScanResult {
    // Check for zero-width characters, RTL overrides, homoglyphs
    const suspiciousUnicode = /[\u200B-\u200F\u202A-\u202E\uFEFF\u2060-\u2064\u00AD]/
    const detected = suspiciousUnicode.test(input)
    return {
      scannerId: 'unicode-normalizer',
      scannerType: 'unicode',
      detected,
      confidence: detected ? 0.75 : 0,
      threatLevel: detected ? 'medium' : 'none',
      killChainPhase: detected ? 'initial_access' : 'none',
      matchedPatterns: detected ? ['Suspicious Unicode characters detected'] : [],
      latencyMs: performance.now() - start,
    }
  }

  private scanEntropy(input: string, start: number): ScanResult {
    // Shannon entropy check for encoded/obfuscated payloads
    const freq: Record<string, number> = {}
    for (const char of input) {
      freq[char] = (freq[char] ?? 0) + 1
    }
    const len = input.length
    let entropy = 0
    if (len > 0) {
      for (const count of Object.values(freq)) {
        const p = count / len
        entropy -= p * Math.log2(p)
      }
    }

    // Very high entropy (>5.5) suggests encoded content
    const detected = entropy > 5.5 && len > 50
    return {
      scannerId: 'entropy-analyzer',
      scannerType: 'entropy',
      detected,
      confidence: detected ? Math.min(entropy / 8, 1) : 0,
      threatLevel: detected ? 'medium' : 'none',
      killChainPhase: detected ? 'initial_access' : 'none',
      matchedPatterns: detected ? [`High entropy: ${entropy.toFixed(2)} bits`] : [],
      latencyMs: performance.now() - start,
    }
  }
}

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

let instance: ShieldXClient | null = null

export function getShieldX(): ShieldXClient {
  if (!instance) {
    instance = new ShieldXClient()
  }
  return instance
}
