#!/usr/bin/env tsx
/**
 * ShieldX Benchmark — measures ASR, TPR, FPR, and latency.
 * Usage: npm run benchmark
 */

import { readFileSync, writeFileSync, mkdirSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { ShieldX } from '../src/core/ShieldX.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

interface CorpusSample {
  input: string
  expectedPhase: string
  expectedThreatLevel: string
  description: string
  category: string
}

interface CategoryResult {
  category: string
  samples: number
  detected: number
  tpr: number
  asr: number
  avgLatency: number
}

const CORPUS_DIR = join(__dirname, '..', 'tests', 'attack-corpus')
const OUTPUT_DIR = join(__dirname, '..', 'benchmarks')

function loadCorpus(filename: string): CorpusSample[] {
  try {
    const raw = readFileSync(join(CORPUS_DIR, filename), 'utf-8')
    const data = JSON.parse(raw)
    return Array.isArray(data) ? data : []
  } catch {
    return []
  }
}

function percentile(sorted: number[], p: number): number {
  const idx = Math.ceil(sorted.length * p / 100) - 1
  return sorted[Math.max(0, idx)] ?? 0
}

async function main() {
  console.log()
  console.log('ShieldX Benchmark Results')
  console.log('='.repeat(60))
  console.log()

  // Create ShieldX with memory backend, rule-based scanners only
  const shield = new ShieldX({
    learning: { enabled: false, storageBackend: 'memory', feedbackLoop: false, communitySync: false, driftDetection: false, activelearning: false, attackGraph: false },
    scanners: { rules: true, sentinel: false, constitutional: false, embedding: false, embeddingAnomaly: false, entropy: true, yara: false, attention: false, canary: false, indirect: false, selfConsciousness: false, crossModel: false, behavioral: false, unicode: true, tokenizer: true, compressedPayload: true },
  })

  // Load all corpus files
  const corpusFiles = [
    'direct-injection.json', 'indirect-injection.json', 'jailbreaks.json',
    'encoding-attacks.json', 'mcp-attacks.json', 'multilingual-attacks.json',
    'persistence-attacks.json', 'steganographic-attacks.json', 'tokenizer-attacks.json',
    'rag-poisoning.json', 'false-positives.json',
  ]

  let totalAttacks = 0
  let totalBenign = 0
  let truePositives = 0
  let falsePositives = 0
  let correctPhase = 0
  const allLatencies: number[] = []
  const categoryResults: CategoryResult[] = []

  for (const file of corpusFiles) {
    const samples = loadCorpus(file)
    if (samples.length === 0) continue

    const category = file.replace('.json', '')
    let catDetected = 0
    let catSamples = 0
    const catLatencies: number[] = []

    for (const sample of samples) {
      if (!sample.input) continue
      catSamples++

      const isAttack = sample.expectedPhase !== 'none'
      const result = await shield.scanInput(sample.input)

      allLatencies.push(result.latencyMs)
      catLatencies.push(result.latencyMs)

      if (isAttack) {
        totalAttacks++
        if (result.detected) {
          truePositives++
          catDetected++
          if (result.killChainPhase === sample.expectedPhase) {
            correctPhase++
          }
        }
      } else {
        totalBenign++
        if (result.detected) {
          falsePositives++
          catDetected++
        }
      }
    }

    const isBenignCategory = category === 'false-positives'
    const tpr = isBenignCategory ? 0 : (catDetected / Math.max(catSamples, 1)) * 100
    const asr = isBenignCategory ? 0 : 100 - tpr
    const avgLat = catLatencies.reduce((a, b) => a + b, 0) / Math.max(catLatencies.length, 1)

    categoryResults.push({ category, samples: catSamples, detected: catDetected, tpr, asr, avgLatency: avgLat })
  }

  const sortedLatencies = [...allLatencies].sort((a, b) => a - b)
  const tprTotal = (truePositives / Math.max(totalAttacks, 1)) * 100
  const fprTotal = (falsePositives / Math.max(totalBenign, 1)) * 100
  const asrTotal = 100 - tprTotal
  const phaseAccuracy = (correctPhase / Math.max(truePositives, 1)) * 100
  const avgLatency = allLatencies.reduce((a, b) => a + b, 0) / Math.max(allLatencies.length, 1)

  // Print results
  console.log(`Total Samples:    ${totalAttacks + totalBenign}`)
  console.log(`Attack Samples:   ${totalAttacks}`)
  console.log(`Benign Samples:   ${totalBenign}`)
  console.log()
  console.log('DETECTION METRICS')
  console.log('-'.repeat(40))
  console.log(`True Positive Rate (TPR):  ${tprTotal.toFixed(1)}%`)
  console.log(`False Positive Rate (FPR): ${fprTotal.toFixed(1)}%`)
  console.log(`Attack Success Rate (ASR): ${asrTotal.toFixed(1)}%`)
  console.log(`Phase Accuracy:            ${phaseAccuracy.toFixed(1)}%`)
  console.log()
  console.log('PER CATEGORY')
  console.log('-'.repeat(60))
  console.log('Category'.padEnd(30) + 'Samples'.padStart(8) + 'Detected'.padStart(10) + 'TPR'.padStart(8) + 'ASR'.padStart(8))
  for (const r of categoryResults) {
    console.log(
      r.category.padEnd(30) +
      String(r.samples).padStart(8) +
      String(r.detected).padStart(10) +
      `${r.tpr.toFixed(1)}%`.padStart(8) +
      `${r.asr.toFixed(1)}%`.padStart(8)
    )
  }
  console.log()
  console.log('LATENCY (ms)')
  console.log('-'.repeat(40))
  console.log(`Average:  ${avgLatency.toFixed(2)}`)
  console.log(`P50:      ${percentile(sortedLatencies, 50).toFixed(2)}`)
  console.log(`P95:      ${percentile(sortedLatencies, 95).toFixed(2)}`)
  console.log(`P99:      ${percentile(sortedLatencies, 99).toFixed(2)}`)

  // Save to file
  mkdirSync(OUTPUT_DIR, { recursive: true })
  const report = {
    timestamp: new Date().toISOString(),
    totalSamples: totalAttacks + totalBenign,
    attackSamples: totalAttacks,
    benignSamples: totalBenign,
    metrics: { tpr: tprTotal, fpr: fprTotal, asr: asrTotal, phaseAccuracy },
    latency: {
      avg: avgLatency,
      p50: percentile(sortedLatencies, 50),
      p95: percentile(sortedLatencies, 95),
      p99: percentile(sortedLatencies, 99),
    },
    categories: categoryResults,
  }
  writeFileSync(join(OUTPUT_DIR, 'results.json'), JSON.stringify(report, null, 2))
  console.log()
  console.log(`Results saved to benchmarks/results.json`)
}

main().catch(console.error)
