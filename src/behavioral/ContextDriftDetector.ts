/**
 * Context drift detection via semantic distance measurement.
 * Detects context window hijacking by tracking cosine distance
 * between current content embeddings and the declared task embedding.
 *
 * Part of Layer 6 — Behavioral Monitoring.
 */

/** Default drift threshold — values above this indicate potential hijacking */
const DEFAULT_DRIFT_THRESHOLD = 0.4

/**
 * Compute the dot product of two equal-length numeric vectors.
 * @param a - First vector
 * @param b - Second vector
 * @returns The scalar dot product
 */
function dotProduct(a: readonly number[], b: readonly number[]): number {
  let sum = 0
  for (let i = 0; i < a.length; i++) {
    const ai = a[i]
    const bi = b[i]
    if (ai !== undefined && bi !== undefined) {
      sum += ai * bi
    }
  }
  return sum
}

/**
 * Compute the Euclidean magnitude of a numeric vector.
 * @param v - The vector
 * @returns The magnitude (L2 norm)
 */
function magnitude(v: readonly number[]): number {
  let sum = 0
  for (const val of v) {
    sum += val * val
  }
  return Math.sqrt(sum)
}

/**
 * Measure cosine distance between two embedding vectors.
 * Returns 0.0 for identical vectors, 1.0 for orthogonal, 2.0 for opposite.
 *
 * @param currentEmbedding - The embedding of the current content
 * @param taskEmbedding - The embedding of the declared task
 * @returns Cosine distance in [0, 2]. Higher = more drift.
 */
export function measureDrift(
  currentEmbedding: readonly number[],
  taskEmbedding: readonly number[],
): number {
  if (currentEmbedding.length === 0 || taskEmbedding.length === 0) {
    return 1.0
  }

  if (currentEmbedding.length !== taskEmbedding.length) {
    return 1.0
  }

  const magA = magnitude(currentEmbedding)
  const magB = magnitude(taskEmbedding)

  if (magA === 0 || magB === 0) {
    return 1.0
  }

  const similarity = dotProduct(currentEmbedding, taskEmbedding) / (magA * magB)
  // Clamp to [-1, 1] to handle floating point imprecision
  const clampedSimilarity = Math.max(-1, Math.min(1, similarity))

  return 1 - clampedSimilarity
}

/**
 * Determine whether a drift score indicates context hijacking.
 *
 * @param driftScore - The cosine distance (from measureDrift)
 * @param threshold - Custom threshold, defaults to 0.4
 * @returns True if the drift exceeds the threshold
 */
export function isHijacked(
  driftScore: number,
  threshold: number = DEFAULT_DRIFT_THRESHOLD,
): boolean {
  return driftScore > threshold
}
