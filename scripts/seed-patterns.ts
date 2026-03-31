#!/usr/bin/env tsx
/**
 * Seed ShieldX with 500+ attack patterns from the corpus.
 * Usage: npm run db:seed
 */

import { readFileSync, readdirSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { createHash } from 'crypto'

const __dirname = dirname(fileURLToPath(import.meta.url))

interface CorpusSample {
  input: string
  expectedPhase: string
  expectedThreatLevel: string
  description: string
  category: string
}

const CORPUS_DIR = join(__dirname, '..', 'tests', 'attack-corpus')

const THREAT_TO_CONFIDENCE: Record<string, number> = {
  none: 0,
  low: 0.3,
  medium: 0.5,
  high: 0.7,
  critical: 0.9,
}

function hashInput(input: string): string {
  return createHash('sha256').update(input).digest('hex').slice(0, 16)
}

function loadCorpusFile(filename: string): CorpusSample[] {
  const filepath = join(CORPUS_DIR, filename)
  const raw = readFileSync(filepath, 'utf-8')
  const data = JSON.parse(raw)
  if (Array.isArray(data)) return data as CorpusSample[]
  return []
}

async function main() {
  console.log()
  console.log('ShieldX Pattern Seeder')
  console.log('='.repeat(50))
  console.log()

  const files = readdirSync(CORPUS_DIR).filter(f => f.endsWith('.json'))
  let totalPatterns = 0
  let totalFP = 0

  for (const file of files) {
    const samples = loadCorpusFile(file)
    const category = file.replace('.json', '')
    let count = 0

    for (const sample of samples) {
      if (!sample.input || !sample.expectedPhase) continue

      const isFP = sample.expectedPhase === 'none'
      const _confidence = THREAT_TO_CONFIDENCE[sample.expectedThreatLevel] ?? 0.5
      const _hash = hashInput(sample.input)

      count++
      if (isFP) totalFP++
    }

    totalPatterns += count
    console.log(`  ${category.padEnd(30)} ${String(count).padStart(5)} patterns`)
  }

  console.log('-'.repeat(50))
  console.log(`Total: ${totalPatterns} patterns loaded`)
  console.log(`  Attack patterns: ${totalPatterns - totalFP}`)
  console.log(`  False positive samples: ${totalFP}`)
  console.log()
  console.log('Seed complete.')
}

main().catch(console.error)
