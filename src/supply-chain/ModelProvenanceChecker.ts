/**
 * Model provenance verification.
 * Checks that ML models come from known-good registries
 * and detects typosquatting in model names.
 */

/** Provenance check result */
interface ProvenanceResult {
  readonly verified: boolean
  readonly source: string
  readonly warnings: readonly string[]
}

/**
 * Known-good model registries and their URL patterns.
 */
const TRUSTED_REGISTRIES: readonly { readonly name: string; readonly patterns: readonly string[] }[] = [
  {
    name: 'huggingface',
    patterns: ['huggingface.co/', 'hf.co/', 'huggingface.co/api/'],
  },
  {
    name: 'ollama',
    patterns: ['ollama.com/', 'registry.ollama.ai/'],
  },
  {
    name: 'pytorch-hub',
    patterns: ['download.pytorch.org/', 'pytorch.org/'],
  },
  {
    name: 'tensorflow-hub',
    patterns: ['tfhub.dev/', 'storage.googleapis.com/tfhub-modules/'],
  },
  {
    name: 'nvidia-ngc',
    patterns: ['catalog.ngc.nvidia.com/', 'nvcr.io/'],
  },
  {
    name: 'openai',
    patterns: ['api.openai.com/', 'cdn.openai.com/'],
  },
  {
    name: 'anthropic',
    patterns: ['api.anthropic.com/'],
  },
  {
    name: 'google-vertex',
    patterns: ['us-docker.pkg.dev/', 'aiplatform.googleapis.com/'],
  },
] as const

/**
 * Well-known model name patterns for typosquatting detection.
 */
const KNOWN_MODEL_NAMES: readonly string[] = [
  'llama', 'mistral', 'codellama', 'phi', 'gemma', 'qwen',
  'vicuna', 'falcon', 'mpt', 'bloom', 'gpt', 'bert',
  'roberta', 't5', 'whisper', 'clip', 'dall-e', 'stable-diffusion',
  'nomic-embed-text', 'all-minilm', 'bge-large', 'gte-large',
  'deepseek', 'command-r', 'claude', 'mixtral', 'solar',
] as const

/**
 * ModelProvenanceChecker — verifies model origin and naming.
 *
 * Performs two checks:
 * 1. Registry verification: model comes from a known-good source
 * 2. Typosquatting detection: model name is suspiciously similar
 *    to a well-known model (potential supply chain attack)
 */
export class ModelProvenanceChecker {
  /**
   * Check the provenance of a model.
   * @param modelId - Model identifier (can be URL, registry path, or name)
   * @returns Provenance result with verification status and warnings
   */
  checkProvenance(modelId: string): ProvenanceResult {
    const warnings: string[] = []
    let source = 'unknown'
    let verified = false

    // Check against trusted registries
    for (const registry of TRUSTED_REGISTRIES) {
      for (const pattern of registry.patterns) {
        if (modelId.includes(pattern)) {
          source = registry.name
          verified = true
          break
        }
      }
      if (verified) break
    }

    if (!verified) {
      warnings.push('model-source-unknown')
    }

    // Check for typosquatting
    const typosquatWarnings = checkTyposquatting(modelId)
    warnings.push(...typosquatWarnings)

    // Check for suspicious patterns in the model ID
    const suspiciousPatterns = checkSuspiciousPatterns(modelId)
    warnings.push(...suspiciousPatterns)

    return Object.freeze({
      verified: verified && warnings.length === 0,
      source,
      warnings: Object.freeze([...warnings]),
    })
  }
}

/**
 * Check for typosquatting by computing edit distance to known model names.
 * Flags names that are very close (but not identical) to popular models.
 */
function checkTyposquatting(modelId: string): string[] {
  const warnings: string[] = []
  const normalizedId = modelId.toLowerCase().replace(/[^a-z0-9]/g, '')

  for (const known of KNOWN_MODEL_NAMES) {
    const normalizedKnown = known.replace(/[^a-z0-9]/g, '')

    // Skip exact matches
    if (normalizedId === normalizedKnown) continue
    if (normalizedId.includes(normalizedKnown)) continue

    // Check edit distance for similarly sized names
    if (Math.abs(normalizedId.length - normalizedKnown.length) > 3) continue

    const distance = levenshteinDistance(normalizedId, normalizedKnown)
    if (distance > 0 && distance <= 2) {
      warnings.push(`typosquatting-risk:${known}:distance=${distance}`)
    }
  }

  return warnings
}

/**
 * Check for suspicious patterns in model IDs.
 */
function checkSuspiciousPatterns(modelId: string): string[] {
  const warnings: string[] = []
  const lower = modelId.toLowerCase()

  // Suspicious TLDs or paths
  if (lower.includes('.ru/') || lower.includes('.cn/') || lower.includes('.tk/')) {
    warnings.push('suspicious-tld')
  }

  // IP addresses instead of domains
  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(modelId)) {
    warnings.push('ip-address-source')
  }

  // Overly long or encoded names
  if (modelId.length > 200) {
    warnings.push('suspicious-name-length')
  }

  // Base64 or encoded segments
  if (/[A-Za-z0-9+/]{40,}={0,2}/.test(modelId)) {
    warnings.push('possible-encoded-segment')
  }

  return warnings
}

/**
 * Levenshtein edit distance between two strings.
 */
function levenshteinDistance(a: string, b: string): number {
  if (a.length === 0) return b.length
  if (b.length === 0) return a.length

  // Use two rows for space efficiency
  let previousRow = Array.from({ length: b.length + 1 }, (_, i) => i)

  for (let i = 0; i < a.length; i++) {
    const currentRow = [i + 1]

    for (let j = 0; j < b.length; j++) {
      const cost = a[i] === b[j] ? 0 : 1
      const prevRowJ = previousRow[j + 1]
      const prevRowJMinus = previousRow[j]
      const currRowJ = currentRow[j]

      if (prevRowJ === undefined || prevRowJMinus === undefined || currRowJ === undefined) continue

      currentRow.push(
        Math.min(
          prevRowJ + 1,        // deletion
          currRowJ + 1,        // insertion
          prevRowJMinus + cost, // substitution
        ),
      )
    }

    previousRow = currentRow
  }

  return previousRow[b.length] ?? 0
}
