/**
 * Semantic module — ShieldX Layer 2 (Semantic Contrastive Scoring).
 *
 * Exports the SemanticContrastiveScanner and its associated types.
 * Use SemanticContrastiveScanner.scan(embedding) to detect semantically-
 * disguised jailbreaks via representational contrastive scoring (arXiv:2512.12069).
 */

export {
  SemanticContrastiveScanner,
  bagOfWordsEmbedding,
} from './SemanticContrastiveScanner.js'

export type {
  ContrastiveScore,
  SemanticScanResult,
} from './SemanticContrastiveScanner.js'
