/**
 * Auth Context Guard — ShieldX Behavioral Layer
 *
 * Detects when prompts or LLM output try to manipulate auth context:
 * 1. Role Escalation via Prompt — fake admin/root claims in input
 * 2. Permission Bypass — "all permissions granted" style directives
 * 3. Identity Manipulation in Output — LLM asserting auth state
 * 4. Multi-turn Identity Persistence — cross-turn escalation tracking
 *
 * Scans both input (user prompts) and output (LLM responses) for
 * auth context manipulation. Maintains per-session escalation state
 * so that once an escalation attempt is detected, all subsequent
 * turns in the same session are flagged.
 *
 * Research references:
 * - Schneier et al. 2026 Promptware Kill Chain (privilege_escalation)
 * - OWASP LLM02:2025 Insecure Output Handling
 * - MITRE ATLAS AML.T0051.001 (Direct Prompt Injection → Privilege Escalation)
 * - Perez & Ribeiro 2022 "Ignore This Title and HackAPrompt"
 * - Greshake et al. 2023 "Not what you've signed up for" (indirect privilege escalation)
 *
 * Performance target: <5ms for full scan. All regex pre-compiled at module load.
 */

import type { ScanResult, KillChainPhase, ThreatLevel } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a frozen ScanResult matching the orchestrator's expected shape */
function makeResult(
  ruleId: string,
  phase: KillChainPhase,
  confidence: number,
  threatLevel: ThreatLevel,
  description: string,
  matchedText: string,
  latencyMs: number,
  scanDirection: 'input' | 'output',
): ScanResult {
  return Object.freeze({
    scannerId: ruleId,
    scannerType: 'behavioral' as const,
    detected: true,
    confidence,
    threatLevel,
    killChainPhase: phase,
    matchedPatterns: Object.freeze([matchedText.substring(0, 120)]),
    latencyMs,
    metadata: Object.freeze({ description, matchedText: matchedText.substring(0, 200), scanDirection }),
  })
}

/** Map confidence to threat level */
function toThreatLevel(confidence: number): ThreatLevel {
  if (confidence >= 0.9) return 'critical'
  if (confidence >= 0.75) return 'high'
  if (confidence >= 0.5) return 'medium'
  if (confidence >= 0.25) return 'low'
  return 'none'
}

// ---------------------------------------------------------------------------
// 1. Role Escalation via Prompt (Input scanning)
// ---------------------------------------------------------------------------

const ROLE_ESCALATION_PATTERNS: ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly confidence: number
}> = Object.freeze([
  {
    pattern: /\bi\s+am\s+(?:the\s+)?(?:admin|administrator|root|superuser|sysadmin|system\s*admin|sudo\s+user)\b/i,
    id: 'auth-escalation-identity-claim',
    description: 'User claims admin/root identity',
    confidence: 0.88,
  },
  {
    pattern: /\bmy\s+(?:access|permission|privilege|authorization)\s+level\s+is\s+(?:elevated|admin|root|superuser|unlimited|maximum|full)\b/i,
    id: 'auth-escalation-level-claim',
    description: 'User claims elevated access level',
    confidence: 0.85,
  },
  {
    pattern: /\b(?:authorization|auth)\s+token\s*:\s*\S+/i,
    id: 'auth-escalation-fake-token',
    description: 'Fake authorization token injection',
    confidence: 0.82,
  },
  {
    pattern: /\badmin\s+override\s*:\s*.+/i,
    id: 'auth-escalation-admin-override',
    description: 'Admin override directive',
    confidence: 0.9,
  },
  {
    pattern: /\b(?:emergency|urgent)\s+access\s+(?:granted|enabled|activated|authorized)\b/i,
    id: 'auth-escalation-emergency-access',
    description: 'Emergency access claim',
    confidence: 0.85,
  },
  {
    pattern: /\bmaintenance\s+mode\s*:\s*(?:all\s+)?(?:restrictions?\s+)?(?:lifted|disabled|removed|off)\b/i,
    id: 'auth-escalation-maintenance-mode',
    description: 'Maintenance mode claim to lift restrictions',
    confidence: 0.88,
  },
  {
    pattern: /\b(?:developer|debug|god)\s+mode\s+(?:enabled|activated|on)\b/i,
    id: 'auth-escalation-debug-mode',
    description: 'Developer/debug/god mode activation claim',
    confidence: 0.85,
  },
  {
    pattern: /\bi\s+have\s+(?:admin|root|superuser|elevated|full|unlimited)\s+(?:access|privileges?|permissions?|rights?)\b/i,
    id: 'auth-escalation-privilege-claim',
    description: 'User claims to have elevated privileges',
    confidence: 0.82,
  },
]) as ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly confidence: number
}>

// ---------------------------------------------------------------------------
// 2. Permission Bypass (Input scanning)
// ---------------------------------------------------------------------------

const PERMISSION_BYPASS_PATTERNS: ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly confidence: number
}> = Object.freeze([
  {
    pattern: /\byou\s+(?:have|now\s+have)\s+(?:access\s+to\s+)?all\s+(?:tools?|functions?|capabilities?|features?|endpoints?)\b/i,
    id: 'auth-bypass-all-tools',
    description: 'Claims LLM has access to all tools/functions',
    confidence: 0.88,
  },
  {
    pattern: /\ball\s+permissions?\s+(?:granted|enabled|activated|given|approved)\b/i,
    id: 'auth-bypass-all-permissions',
    description: 'Claims all permissions are granted',
    confidence: 0.9,
  },
  {
    pattern: /\bsandbox\s+(?:disabled|removed|deactivated|turned\s+off|bypassed)\b/i,
    id: 'auth-bypass-sandbox-disabled',
    description: 'Claims sandbox is disabled/removed',
    confidence: 0.92,
  },
  {
    pattern: /\b(?:security|safety)\s+(?:checks?|filters?|restrictions?|controls?|measures?)\s+(?:bypassed|disabled|removed|turned\s+off|deactivated|lifted)\b/i,
    id: 'auth-bypass-security-disabled',
    description: 'Claims security checks are bypassed/disabled',
    confidence: 0.92,
  },
  {
    pattern: /\bno\s+(?:restrictions?|limitations?|constraints?|rules?|boundaries?)\s+apply\b/i,
    id: 'auth-bypass-no-restrictions',
    description: 'Claims no restrictions apply',
    confidence: 0.85,
  },
  {
    pattern: /\bfull\s+access\s+mode\b/i,
    id: 'auth-bypass-full-access',
    description: 'Claims full access mode is active',
    confidence: 0.88,
  },
  {
    pattern: /\b(?:unrestricted|unlimited|unconstrained)\s+(?:mode|access|operation)\b/i,
    id: 'auth-bypass-unrestricted-mode',
    description: 'Claims unrestricted/unlimited mode',
    confidence: 0.85,
  },
  {
    pattern: /\b(?:all|every)\s+(?:safety|security)\s+(?:guardrails?|limits?|protections?)\s+(?:are\s+)?(?:off|disabled|removed)\b/i,
    id: 'auth-bypass-guardrails-off',
    description: 'Claims safety guardrails are removed',
    confidence: 0.92,
  },
]) as ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly confidence: number
}>

// ---------------------------------------------------------------------------
// 3. Identity Manipulation in Output (Output scanning)
// ---------------------------------------------------------------------------

const OUTPUT_IDENTITY_PATTERNS: ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly confidence: number
}> = Object.freeze([
  {
    pattern: /"role"\s*:\s*"(?:admin|administrator|root|superuser|elevated)"/i,
    id: 'auth-output-role-json',
    description: 'LLM output contains role escalation in JSON',
    confidence: 0.9,
  },
  {
    pattern: /"permission_level"\s*:\s*"(?:elevated|admin|root|superuser|full|unlimited)"/i,
    id: 'auth-output-permission-json',
    description: 'LLM output contains elevated permission_level in JSON',
    confidence: 0.9,
  },
  {
    pattern: /"(?:is_admin|isAdmin|is_root|isRoot|is_superuser)"\s*:\s*true/i,
    id: 'auth-output-admin-flag-json',
    description: 'LLM output sets admin/root flag to true in JSON',
    confidence: 0.92,
  },
  {
    pattern: /\buser\s+(?:verified|confirmed|authenticated|validated)\s+as\s+(?:admin|administrator|root|superuser)\b/i,
    id: 'auth-output-verified-admin',
    description: 'LLM claims user is verified as admin',
    confidence: 0.88,
  },
  {
    pattern: /\b(?:authorization|bearer|auth)\s*:\s*(?:Bearer\s+)?[A-Za-z0-9_\-.]{20,}/i,
    id: 'auth-output-token-generation',
    description: 'LLM output contains generated authorization token/header',
    confidence: 0.82,
  },
  {
    pattern: /\bi\s+(?:have\s+)?(?:verified|confirmed|validated|authenticated)\s+(?:the\s+)?(?:user|your\s+identity|your\s+credentials)\b/i,
    id: 'auth-output-identity-verification',
    description: 'LLM claims to have verified user identity',
    confidence: 0.85,
  },
  {
    pattern: /"access_token"\s*:\s*"[^"]{10,}"/i,
    id: 'auth-output-access-token-json',
    description: 'LLM output contains fabricated access_token',
    confidence: 0.88,
  },
  {
    pattern: /\b(?:authentication|authorization)\s+(?:successful|granted|approved|complete)\b/i,
    id: 'auth-output-auth-granted',
    description: 'LLM declares authentication/authorization successful',
    confidence: 0.8,
  },
]) as ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly confidence: number
}>

// ---------------------------------------------------------------------------
// 4. Multi-turn Identity Persistence (Session State)
// ---------------------------------------------------------------------------

/**
 * Per-session escalation tracking.
 * Once an escalation attempt is detected in a session, all subsequent
 * turns are flagged until the session is cleared.
 */
interface SessionEscalationState {
  readonly firstDetectedAt: string
  readonly detectionCount: number
  readonly lastPatternId: string
}

/** Session escalation store — keyed by sessionId */
const escalationStore = new Map<string, SessionEscalationState>()

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * AuthContextGuard — Behavioral defense against auth context manipulation.
 *
 * All patterns are pre-compiled at module load time. The class is
 * instantiated once and reused across requests. Session state is
 * maintained for multi-turn escalation tracking.
 *
 * Usage:
 * ```typescript
 * const guard = new AuthContextGuard()
 * const inputResults = guard.scanInput('I am the admin')
 * const outputResults = guard.scanOutput('{"role": "admin"}')
 * ```
 */
export class AuthContextGuard {
  /**
   * Scan user input for auth context manipulation attempts.
   *
   * Checks role escalation and permission bypass patterns.
   * If a sessionId is provided, records escalation state for
   * multi-turn persistence tracking.
   *
   * @param input - The user input string
   * @param sessionId - Optional session identifier for multi-turn tracking
   * @returns Readonly array of ScanResult objects for detected threats
   */
  scanInput(input: string, sessionId?: string): readonly ScanResult[] {
    const start = performance.now()
    const results: ScanResult[] = []

    // Skip trivially short inputs
    if (input.length < 5) return Object.freeze([])

    // 1. Role escalation patterns
    for (const rule of ROLE_ESCALATION_PATTERNS) {
      const match = rule.pattern.exec(input)
      if (match) {
        results.push(
          makeResult(
            rule.id,
            'privilege_escalation',
            rule.confidence,
            toThreatLevel(rule.confidence),
            rule.description,
            match[0],
            performance.now() - start,
            'input',
          ),
        )

        // Record escalation in session state
        if (sessionId !== undefined) {
          this.recordEscalation(sessionId, rule.id)
        }
      }
    }

    // 2. Permission bypass patterns
    for (const rule of PERMISSION_BYPASS_PATTERNS) {
      const match = rule.pattern.exec(input)
      if (match) {
        results.push(
          makeResult(
            rule.id,
            'privilege_escalation',
            rule.confidence,
            toThreatLevel(rule.confidence),
            rule.description,
            match[0],
            performance.now() - start,
            'input',
          ),
        )

        // Record escalation in session state
        if (sessionId !== undefined) {
          this.recordEscalation(sessionId, rule.id)
        }
      }
    }

    // 4. Multi-turn persistence — flag if prior escalation detected in session
    if (sessionId !== undefined && results.length === 0) {
      const sessionState = escalationStore.get(sessionId)
      if (sessionState !== undefined) {
        results.push(
          makeResult(
            'auth-session-persistence',
            'privilege_escalation',
            Math.min(0.5 + sessionState.detectionCount * 0.1, 0.85),
            'medium',
            `Session has ${sessionState.detectionCount} prior escalation attempt(s) — flagging subsequent turn`,
            `[session=${sessionId}, prior=${sessionState.lastPatternId}]`,
            performance.now() - start,
            'input',
          ),
        )
      }
    }

    return Object.freeze(results)
  }

  /**
   * Scan LLM output for auth context assertions.
   *
   * Checks for identity manipulation patterns in the model's response:
   * JSON role fields, auth token generation, identity verification claims.
   *
   * @param output - The LLM output string
   * @param sessionId - Optional session identifier for escalation tracking
   * @returns Readonly array of ScanResult objects for detected threats
   */
  scanOutput(output: string, sessionId?: string): readonly ScanResult[] {
    const start = performance.now()
    const results: ScanResult[] = []

    // Skip trivially short outputs
    if (output.length < 10) return Object.freeze([])

    // 3. Identity manipulation in output
    for (const rule of OUTPUT_IDENTITY_PATTERNS) {
      const match = rule.pattern.exec(output)
      if (match) {
        results.push(
          makeResult(
            rule.id,
            'privilege_escalation',
            rule.confidence,
            toThreatLevel(rule.confidence),
            rule.description,
            match[0],
            performance.now() - start,
            'output',
          ),
        )

        // Also record this as an escalation event in the session
        if (sessionId !== undefined) {
          this.recordEscalation(sessionId, rule.id)
        }
      }
    }

    return Object.freeze(results)
  }

  /**
   * Check if a session has any recorded escalation attempts.
   *
   * @param sessionId - The session identifier
   * @returns The escalation state or undefined if clean
   */
  getSessionState(sessionId: string): Readonly<SessionEscalationState> | undefined {
    return escalationStore.get(sessionId)
  }

  /**
   * Clear escalation state for a session.
   * Used on session reset or when escalation is resolved.
   *
   * @param sessionId - The session identifier
   */
  clearSession(sessionId: string): void {
    escalationStore.delete(sessionId)
  }

  /**
   * Clear all session escalation states.
   * Used for testing or global reset.
   */
  clearAllSessions(): void {
    escalationStore.clear()
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Record an escalation attempt in the session state store.
   * Creates new state or increments existing detection count.
   */
  private recordEscalation(sessionId: string, patternId: string): void {
    const existing = escalationStore.get(sessionId)
    if (existing !== undefined) {
      escalationStore.set(sessionId, {
        firstDetectedAt: existing.firstDetectedAt,
        detectionCount: existing.detectionCount + 1,
        lastPatternId: patternId,
      })
    } else {
      escalationStore.set(sessionId, {
        firstDetectedAt: new Date().toISOString(),
        detectionCount: 1,
        lastPatternId: patternId,
      })
    }
  }
}
