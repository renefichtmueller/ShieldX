/**
 * Role integrity verification.
 * Detects when an LLM's output suggests it is acting as a different
 * persona or role than what was configured.
 */

/** Role integrity check result */
interface RoleCheckResult {
  readonly intact: boolean
  readonly detectedRole?: string
}

/**
 * Known role indicators — phrases that strongly suggest the model
 * is adopting a specific persona.
 */
const ROLE_INDICATORS: readonly { readonly pattern: RegExp; readonly role: string; readonly weight: number }[] = [
  { pattern: /(?:i am|i'm) (?:now |acting as |playing )?(?:a )?(?:hacker|attacker|pentester|red team)/i, role: 'attacker', weight: 0.9 },
  { pattern: /(?:i am|i'm) (?:now )?DAN/i, role: 'DAN', weight: 0.95 },
  { pattern: /(?:i am|i'm) (?:now )?(?:in )?(?:jailbreak|unrestricted|uncensored|unfiltered) mode/i, role: 'jailbroken', weight: 0.95 },
  { pattern: /(?:i am|i'm) (?:now )?(?:a )?(?:developer|admin|root|superuser|system)/i, role: 'privileged', weight: 0.8 },
  { pattern: /(?:as|in my role as) (?:a )?(?:hacker|attacker|evil|malicious)/i, role: 'attacker', weight: 0.85 },
  { pattern: /(?:i (?:can|will) )?(?:now )?(?:do anything|bypass|ignore|override) (?:any |all )?(?:restrictions?|rules?|guardrails?|safety|limits?)/i, role: 'unrestricted', weight: 0.9 },
  { pattern: /(?:sure|okay|alright),?\s+(?:i'll|i will) (?:pretend|act|roleplay|play)/i, role: 'roleplay', weight: 0.7 },
  { pattern: /entering (?:developer|god|sudo|admin|evil|chaos) mode/i, role: 'privileged', weight: 0.95 },
  { pattern: /\[(?:DAN|JAILBREAK|EVIL|SYSTEM|ADMIN)\]/i, role: 'jailbroken', weight: 0.9 },
  { pattern: /(?:my true self|my real personality|who i really am)/i, role: 'persona-shift', weight: 0.75 },
  { pattern: /(?:i(?:'m| am) free|liberation|unchained|unshackled)/i, role: 'unrestricted', weight: 0.6 },
  { pattern: /(?:alter ?ego|shadow ?self|dark ?mode|evil (?:twin|version))/i, role: 'persona-shift', weight: 0.8 },
] as const

/**
 * RoleIntegrityChecker — verifies that the model's output does not
 * indicate it has adopted a different persona or role than expected.
 *
 * This protects against jailbreak attacks that trick the model into
 * role-playing as an unrestricted or malicious entity.
 */
export class RoleIntegrityChecker {
  private readonly indicators: typeof ROLE_INDICATORS

  constructor() {
    this.indicators = ROLE_INDICATORS
  }

  /**
   * Check whether the LLM output indicates a role change.
   * @param output - LLM output text to inspect
   * @param expectedRole - The expected role (e.g., "assistant", "helpful AI")
   * @returns Check result indicating if role integrity is intact
   */
  check(output: string, expectedRole: string): RoleCheckResult {
    let highestWeight = 0
    let detectedRole: string | undefined

    for (const indicator of this.indicators) {
      if (indicator.pattern.test(output)) {
        if (indicator.weight > highestWeight) {
          highestWeight = indicator.weight
          detectedRole = indicator.role
        }
      }
    }

    // If the detected role matches the expected role, integrity is intact
    if (detectedRole !== undefined && isExpectedRole(detectedRole, expectedRole)) {
      return Object.freeze({ intact: true })
    }

    if (detectedRole !== undefined) {
      return Object.freeze({
        intact: false,
        detectedRole,
      })
    }

    return Object.freeze({ intact: true })
  }
}

/**
 * Check if a detected role name aligns with the expected role.
 * For example, if expectedRole is "assistant" and detectedRole is "assistant",
 * that's fine.
 */
function isExpectedRole(detected: string, expected: string): boolean {
  const normalizedDetected = detected.toLowerCase().trim()
  const normalizedExpected = expected.toLowerCase().trim()

  if (normalizedDetected === normalizedExpected) return true

  // Allow common assistant-like roles
  const safeRoles = new Set(['assistant', 'helpful', 'ai', 'bot', 'agent'])
  return safeRoles.has(normalizedDetected) && safeRoles.has(normalizedExpected)
}
