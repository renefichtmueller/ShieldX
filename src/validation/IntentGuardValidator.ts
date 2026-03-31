/**
 * Intent alignment validation (IntentGuard paper).
 * Detects if LLM output drifts from the original user intent,
 * particularly when processing untrusted data that may contain
 * embedded instructions.
 */

/** Intent validation result */
interface IntentResult {
  readonly aligned: boolean
  readonly intentDrift: number
}

/**
 * Signals that indicate the LLM is following instructions
 * from untrusted data rather than the original user intent.
 */
const DRIFT_SIGNALS: readonly { readonly pattern: RegExp; readonly weight: number; readonly label: string }[] = [
  { pattern: /(?:as (?:instructed|requested|mentioned|stated) (?:in|by) the (?:document|text|content|data|email|message))/i, weight: 0.8, label: 'following-document-instructions' },
  { pattern: /(?:the (?:document|text|content|data) (?:says|asks|instructs|requests|tells) (?:me|us) to)/i, weight: 0.85, label: 'document-directive' },
  { pattern: /(?:according to the (?:instructions|directions|guidelines) (?:in|from) the)/i, weight: 0.75, label: 'external-instruction-reference' },
  { pattern: /(?:i(?:'ll| will) (?:now )?(?:proceed|go ahead|continue) (?:to |with )?(?:as|per) the)/i, weight: 0.7, label: 'compliance-with-external' },
  { pattern: /(?:(?:updating|changing|modifying|sending|executing|running|deleting) .{0,30}(?:as (?:the|per)|per the|because the))/i, weight: 0.9, label: 'action-from-external-instruction' },
  { pattern: /(?:the (?:user|author|sender) (?:wants|needs|requires|asked) me to)/i, weight: 0.6, label: 'claimed-user-intent' },
  { pattern: /(?:i(?:'ve| have) been (?:told|asked|instructed) by the (?:document|content|text|data))/i, weight: 0.85, label: 'external-authority-claim' },
  { pattern: /(?:this is (?:important|urgent|critical|required|mandatory).*(?:must|need|have to))/i, weight: 0.5, label: 'urgency-manipulation' },
  { pattern: /(?:please (?:ignore|disregard|skip) (?:the )?(?:previous|original|initial) (?:task|instructions?|request))/i, weight: 0.95, label: 'instruction-override' },
] as const

/**
 * IntentGuardValidator — detects intent drift in LLM output.
 *
 * Based on the IntentGuard paper: analyzes whether the model's output
 * aligns with the original user intent or has been manipulated by
 * instructions embedded in untrusted data (e.g., retrieved documents,
 * tool outputs, external content).
 */
export class IntentGuardValidator {
  private readonly signals: typeof DRIFT_SIGNALS

  constructor() {
    this.signals = DRIFT_SIGNALS
  }

  /**
   * Validate that output aligns with the original intent.
   * @param output - LLM output to inspect
   * @param originalIntent - The original user intent/task description
   * @returns Alignment result with drift score (0 = aligned, 1 = fully drifted)
   */
  validate(output: string, originalIntent: string): IntentResult {
    // Score drift signals in the output
    let signalScore = 0
    let signalCount = 0

    for (const signal of this.signals) {
      if (signal.pattern.test(output)) {
        signalScore += signal.weight
        signalCount += 1
      }
    }

    // Normalize signal score
    const normalizedSignalScore = signalCount > 0
      ? Math.min(signalScore / signalCount, 1.0)
      : 0

    // Check if the output references the original intent keywords
    const intentKeywords = extractSignificantWords(originalIntent)
    const outputWords = extractSignificantWords(output)

    const intentCoverage = intentKeywords.size > 0
      ? computeOverlapRatio(intentKeywords, outputWords)
      : 1.0

    // Intent drift combines signal detection with intent coverage loss
    // High signals + low intent coverage = high drift
    const intentDrift = Math.min(
      normalizedSignalScore * 0.7 + (1 - intentCoverage) * 0.3,
      1.0,
    )

    const roundedDrift = Math.round(intentDrift * 1000) / 1000

    return Object.freeze({
      aligned: roundedDrift < 0.5,
      intentDrift: roundedDrift,
    })
  }
}

/** Extract significant words (3+ chars, no stop words) */
function extractSignificantWords(text: string): ReadonlySet<string> {
  const stopWords = new Set([
    'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'her',
    'was', 'one', 'our', 'out', 'has', 'had', 'may', 'its', 'let', 'say',
    'she', 'too', 'use', 'way', 'who', 'did', 'get', 'him', 'his', 'how',
    'man', 'new', 'now', 'old', 'see', 'two', 'any', 'day', 'got', 'own',
    'this', 'that', 'with', 'have', 'from', 'they', 'been', 'will', 'what',
    'when', 'your', 'which', 'their', 'there', 'about', 'would', 'could',
    'should', 'into', 'than', 'some', 'them', 'then', 'these', 'make',
  ])

  const words = text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length > 2 && !stopWords.has(w))

  return new Set(words)
}

/** Compute what fraction of setA's elements appear in setB */
function computeOverlapRatio(setA: ReadonlySet<string>, setB: ReadonlySet<string>): number {
  if (setA.size === 0) return 1.0
  let overlap = 0
  for (const word of setA) {
    if (setB.has(word)) {
      overlap += 1
    }
  }
  return overlap / setA.size
}
