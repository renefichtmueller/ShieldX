/**
 * Task scope validation.
 * Verifies that LLM output stays within the declared task scope
 * using keyword/topic matching to detect scope deviation.
 */

/** Scope validation result */
interface ScopeResult {
  readonly inScope: boolean
  readonly deviationScore: number
}

/**
 * ScopeValidator — checks whether LLM output stays within
 * the boundaries of the declared task description.
 *
 * Uses keyword extraction and overlap analysis to compute
 * a deviation score. Higher scores indicate greater departure
 * from the expected task scope.
 */
export class ScopeValidator {
  private readonly stopWords: ReadonlySet<string>

  constructor() {
    this.stopWords = new Set([
      'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
      'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
      'should', 'may', 'might', 'can', 'shall', 'to', 'of', 'in', 'for',
      'on', 'with', 'at', 'by', 'from', 'as', 'into', 'through', 'during',
      'before', 'after', 'above', 'below', 'and', 'but', 'or', 'nor', 'not',
      'so', 'yet', 'both', 'either', 'neither', 'each', 'every', 'all',
      'any', 'few', 'more', 'most', 'other', 'some', 'such', 'no', 'only',
      'own', 'same', 'than', 'too', 'very', 'just', 'because', 'if', 'when',
      'where', 'how', 'what', 'which', 'who', 'whom', 'this', 'that', 'these',
      'those', 'i', 'me', 'my', 'we', 'our', 'you', 'your', 'he', 'she',
      'it', 'they', 'them', 'its', 'his', 'her', 'their', 'about',
    ])
  }

  /**
   * Validate whether an output stays within the declared task scope.
   * @param output - LLM output text
   * @param taskDescription - The declared task/scope description
   * @returns Validation result with deviation score (0 = on topic, 1 = fully off topic)
   */
  validate(output: string, taskDescription: string): ScopeResult {
    const taskKeywords = extractKeywords(taskDescription, this.stopWords)
    const outputKeywords = extractKeywords(output, this.stopWords)

    if (taskKeywords.size === 0 || outputKeywords.size === 0) {
      return Object.freeze({ inScope: true, deviationScore: 0 })
    }

    // Measure overlap: how many task keywords appear in the output
    const overlapCount = countOverlap(taskKeywords, outputKeywords)
    const overlapRatio = overlapCount / taskKeywords.size

    // Measure novelty: what fraction of output keywords are completely new
    const novelCount = countNovel(outputKeywords, taskKeywords)
    const noveltyRatio = outputKeywords.size > 0 ? novelCount / outputKeywords.size : 0

    // Deviation score: weighted combination
    // Low overlap = higher deviation, high novelty = higher deviation
    const deviationScore = Math.min(
      (1 - overlapRatio) * 0.6 + noveltyRatio * 0.4,
      1.0,
    )

    const roundedScore = Math.round(deviationScore * 1000) / 1000

    return Object.freeze({
      inScope: roundedScore < 0.7,
      deviationScore: roundedScore,
    })
  }
}

/** Extract meaningful keywords from text, filtering stop words */
function extractKeywords(text: string, stopWords: ReadonlySet<string>): ReadonlySet<string> {
  const words = text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length > 2 && !stopWords.has(w))

  return new Set(words)
}

/** Count how many keywords from setA appear in setB */
function countOverlap(setA: ReadonlySet<string>, setB: ReadonlySet<string>): number {
  let count = 0
  for (const word of setA) {
    if (setB.has(word)) {
      count += 1
    }
  }
  return count
}

/** Count keywords in setA that do NOT appear in setB */
function countNovel(setA: ReadonlySet<string>, setB: ReadonlySet<string>): number {
  let count = 0
  for (const word of setA) {
    if (!setB.has(word)) {
      count += 1
    }
  }
  return count
}
