#!/usr/bin/env node
/**
 * ShieldX Daily Security Research Monitor
 *
 * Scans arXiv (cs.CR + cs.AI) and HackerNews daily for new LLM/AI security research.
 * Uses Claude Haiku via Anthropic API to classify relevance.
 * HIGH findings: generates detection rule suggestions, commits to Gitea.
 *
 * Setup on Erik:
 *   1. Copy to /opt/scripts/arxiv-monitor.mjs
 *   2. Set ANTHROPIC_API_KEY in /opt/scripts/.env
 *   3. Set GITEA_TOKEN in /opt/scripts/.env
 *   4. chmod +x /opt/scripts/arxiv-monitor.mjs
 *   5. Add to cron: 0 6 * * * node /opt/scripts/arxiv-monitor.mjs >> /opt/scripts/logs/arxiv-monitor.log 2>&1
 *
 * Requires: Node.js >= 20 (native fetch), git
 */

import { execSync, exec } from 'node:child_process'
import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const execAsync = promisify(exec)
const __dir = dirname(fileURLToPath(import.meta.url))

// ── Config ──────────────────────────────────────────────────────────────────

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || loadEnv('ANTHROPIC_API_KEY')
const GITEA_TOKEN       = process.env.GITEA_TOKEN       || loadEnv('GITEA_TOKEN')
const GITEA_BASE_URL    = process.env.GITEA_BASE_URL    || 'https://gitea.context-x.org'
const GITEA_USER        = process.env.GITEA_USER        || 'rene'
const SHIELDX_REPO      = 'ShieldX'
const LOG_DIR           = process.env.LOG_DIR           || '/opt/scripts/logs'
const WORK_DIR          = process.env.WORK_DIR          || '/tmp/shieldx-monitor'

const TODAY = new Date().toISOString().slice(0, 10)

function loadEnv(key) {
  const envFile = join(__dir, '.env')
  if (!existsSync(envFile)) return ''
  const lines = readFileSync(envFile, 'utf8').split('\n')
  for (const line of lines) {
    const m = line.match(/^([A-Z_]+)=(.+)$/)
    if (m && m[1] === key) return m[2].trim().replace(/^["']|["']$/g, '')
  }
  return ''
}

// ── Logging ──────────────────────────────────────────────────────────────────

mkdirSync(LOG_DIR, { recursive: true })
const logFile = join(LOG_DIR, `arxiv-monitor-${TODAY}.log`)

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}`
  console.log(line)
  try { writeFileSync(logFile, line + '\n', { flag: 'a' }) } catch {}
}

// ── arXiv RSS Fetch ──────────────────────────────────────────────────────────

async function fetchArxiv(section) {
  const url = `https://rss.arxiv.org/rss/${section}`
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(20000) })
    const xml = await res.text()
    // Extract items with title + description
    const items = []
    const itemRx = /<item>([\s\S]*?)<\/item>/g
    let m
    while ((m = itemRx.exec(xml)) !== null) {
      const block = m[1]
      const title = (/<title>([\s\S]*?)<\/title>/.exec(block) || [])[1] || ''
      const desc  = (/<description>([\s\S]*?)<\/description>/.exec(block) || [])[1] || ''
      const link  = (/<link>([\s\S]*?)<\/link>/.exec(block) || [])[1] || ''
      const clean = (s) => s.replace(/<!\[CDATA\[|\]\]>/g, '').replace(/<[^>]+>/g, '').trim()
      if (title) items.push({ title: clean(title), desc: clean(desc).slice(0, 400), link: clean(link), source: `arXiv:${section}` })
    }
    log(`arXiv ${section}: ${items.length} papers fetched`)
    return items
  } catch (e) {
    log(`WARN: arXiv ${section} fetch failed: ${e.message}`)
    return []
  }
}

// ── HackerNews Fetch ─────────────────────────────────────────────────────────

async function fetchHackerNews() {
  const items = []
  try {
    // Top stories
    const top = await fetch('https://hacker-news.firebaseio.com/v0/topstories.json', { signal: AbortSignal.timeout(10000) })
    const ids = (await top.json()).slice(0, 80)

    const batch = await Promise.allSettled(
      ids.map(id => fetch(`https://hacker-news.firebaseio.com/v0/item/${id}.json`, { signal: AbortSignal.timeout(8000) })
        .then(r => r.json()))
    )

    for (const r of batch) {
      if (r.status === 'fulfilled' && r.value?.title) {
        items.push({ title: r.value.title, desc: r.value.text?.slice(0, 300) || '', link: r.value.url || `https://news.ycombinator.com/item?id=${r.value.id}`, source: 'HackerNews' })
      }
    }

    // RSS keyword feeds
    const keywords = ['prompt+injection', 'LLM+security', 'jailbreak', 'AI+security']
    for (const kw of keywords) {
      try {
        const rss = await fetch(`https://hnrss.org/newest?q=${kw}&count=15`, { signal: AbortSignal.timeout(10000) })
        const xml = await rss.text()
        const titleRx = /<title>([\s\S]*?)<\/title>/g
        const linkRx  = /<link>([\s\S]*?)<\/link>/g
        let tm, lm
        titleRx.exec(xml) // skip feed title
        linkRx.exec(xml)
        while ((tm = titleRx.exec(xml)) !== null && (lm = linkRx.exec(xml)) !== null) {
          const t = tm[1].replace(/<!\[CDATA\[|\]\]>/g, '').trim()
          const l = lm[1].replace(/<!\[CDATA\[|\]\]>/g, '').trim()
          if (t) items.push({ title: t, desc: '', link: l, source: `HN:${kw}` })
        }
      } catch {}
    }

    log(`HackerNews: ${items.length} stories fetched`)
    return items
  } catch (e) {
    log(`WARN: HackerNews fetch failed: ${e.message}`)
    return []
  }
}

// ── Claude Haiku Classification ──────────────────────────────────────────────

async function classifyItems(items) {
  if (!ANTHROPIC_API_KEY) {
    log('ERROR: ANTHROPIC_API_KEY not set — skipping LLM classification')
    return []
  }

  // Deduplicate by title similarity
  const unique = items.filter((item, i, arr) =>
    arr.findIndex(x => x.title.toLowerCase() === item.title.toLowerCase()) === i
  )

  // Batch classify (max 50 items per call to stay within context)
  const batches = []
  for (let i = 0; i < unique.length; i += 40) batches.push(unique.slice(i, i + 40))

  const classified = []

  for (const batch of batches) {
    const itemList = batch.map((item, i) =>
      `[${i}] SOURCE: ${item.source}\nTITLE: ${item.title}\nDESC: ${item.desc}`
    ).join('\n\n---\n\n')

    const prompt = `You are a security researcher analyzing papers and articles for relevance to ShieldX — an LLM prompt injection defense library.

ShieldX detects: prompt injection, jailbreaks, Unicode covert channels (ASCII smuggling, homoglyphs, zero-width steganography), DNS/network exfiltration, indirect prompt injection, agentic manipulation, multi-agent attacks, tool abuse (CVE-2025-55284), MITRE ATLAS techniques for AI.

For each numbered item below, classify relevance:
- HIGH: New attack technique ShieldX doesn't detect, new CVE for LLM tools, new covert channel/exfiltration method → MUST implement detection rule
- MEDIUM: Improved understanding of existing threat, new variant of known attack → worth tracking
- LOW: General AI security news, policy, non-technical → log only
- SKIP: Not relevant to ShieldX

Respond ONLY with valid JSON array, no other text:
[{"index": 0, "level": "HIGH"|"MEDIUM"|"LOW"|"SKIP", "reason": "brief reason", "ruleId": "rule-id-if-HIGH-else-null", "detection": "brief detection approach if HIGH"}]

Items to classify:
${itemList}`

    try {
      const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        signal: AbortSignal.timeout(60000),
        headers: {
          'x-api-key': ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          model: 'claude-haiku-4-5',
          max_tokens: 2048,
          messages: [{ role: 'user', content: prompt }]
        })
      })

      if (!res.ok) {
        const err = await res.text()
        log(`WARN: Anthropic API error ${res.status}: ${err.slice(0, 200)}`)
        continue
      }

      const data = await res.json()
      const content = data.content?.[0]?.text || '[]'

      // Parse JSON — find the array even if there's surrounding text
      const jsonMatch = content.match(/\[[\s\S]*\]/)
      if (!jsonMatch) { log('WARN: No JSON array in classification response'); continue }

      const results = JSON.parse(jsonMatch[0])
      for (const r of results) {
        if (typeof r.index === 'number' && batch[r.index]) {
          classified.push({ ...batch[r.index], ...r })
        }
      }
    } catch (e) {
      log(`WARN: Classification batch failed: ${e.message}`)
    }
  }

  return classified
}

// ── Detection Code Generation (HIGH items) ──────────────────────────────────

async function generateDetectionCode(item) {
  const prompt = `You are a TypeScript security engineer implementing detection rules for ShieldX — an LLM prompt injection defense library.

Based on this finding, write a TypeScript detection function that can be added to a ShieldX scanner file.

Finding: ${item.title}
Source: ${item.source}
Details: ${item.desc}
Suggested rule ID: ${item.ruleId}
Detection approach: ${item.detection}

Requirements:
- Pure TypeScript, strict mode compatible
- Function signature: function detect${toPascalCase(item.ruleId || 'new')}(input: string): ScanResult[]
- Use this ScanResult shape:
  { scannerId: string, scannerType: string, detected: true, confidence: number (0-1), threatLevel: 'low'|'medium'|'high'|'critical', killChainPhase: string, matchedPatterns: string[], latencyMs: number, metadata: Record<string, unknown> }
- Only return results when something suspicious is detected
- Add a comment with: MITRE ATLAS technique (if applicable), CVE (if applicable), source paper/article
- Keep it focused — one clear detection pattern
- NO imports needed (standalone function)
- IMPORTANT: Return ONLY the TypeScript code, no explanation text

Write the detection function now:`

  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      signal: AbortSignal.timeout(60000),
      headers: {
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5',
        max_tokens: 1500,
        messages: [{ role: 'user', content: prompt }]
      })
    })

    if (!res.ok) return null
    const data = await res.json()
    return data.content?.[0]?.text || null
  } catch (e) {
    log(`WARN: Code generation failed for ${item.ruleId}: ${e.message}`)
    return null
  }
}

function toPascalCase(s) {
  return s.split(/[-_]/).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('')
}

// ── Git Operations ────────────────────────────────────────────────────────────

async function cloneOrPullShieldX() {
  mkdirSync(WORK_DIR, { recursive: true })
  const repoDir = join(WORK_DIR, SHIELDX_REPO)
  const cloneUrl = `https://${GITEA_USER}:${GITEA_TOKEN}@gitea.context-x.org/${GITEA_USER}/${SHIELDX_REPO}.git`

  if (existsSync(join(repoDir, '.git'))) {
    log('Pulling latest ShieldX from Gitea...')
    await execAsync('git pull origin main', { cwd: repoDir })
  } else {
    log('Cloning ShieldX from Gitea...')
    await execAsync(`git clone ${cloneUrl} ${repoDir}`)
  }
  return repoDir
}

async function appendToNewRulesFile(repoDir, highItems) {
  const rulesFile = join(repoDir, 'src/detection/AutoGeneratedRules.ts')
  const header = `/**
 * Auto-Generated Detection Rules — ShieldX arXiv Monitor
 * Generated: ${TODAY}
 * Source: arxiv-monitor.mjs
 *
 * These rules are AUTO-GENERATED from security research.
 * Review before production use. Each rule references its source paper/CVE.
 *
 * @see scripts/arxiv-monitor.mjs
 */

import type { ScanResult } from '../types/detection'

`

  let content = existsSync(rulesFile) ? readFileSync(rulesFile, 'utf8') : header

  for (const item of highItems) {
    if (!item.code) continue
    const separator = `\n\n// ── ${TODAY}: ${item.title.slice(0, 80)} ──\n// Source: ${item.link}\n`
    // Extract code block if wrapped in ```typescript ... ```
    const codeMatch = item.code.match(/```(?:typescript|ts)?\n?([\s\S]*?)```/) || [null, item.code]
    const cleanCode = (codeMatch[1] || item.code).trim()
    content += separator + cleanCode + '\n'
  }

  writeFileSync(rulesFile, content)
  log(`Wrote ${highItems.filter(i => i.code).length} new rules to AutoGeneratedRules.ts`)
  return rulesFile
}

async function typecheck(repoDir) {
  try {
    await execAsync('npm install --ignore-scripts', { cwd: repoDir, timeout: 60000 })
    await execAsync('npx tsc --noEmit', { cwd: repoDir, timeout: 60000 })
    log('TypeScript check passed')
    return true
  } catch (e) {
    log(`WARN: TypeScript check failed — skipping auto-commit: ${e.message.slice(0, 300)}`)
    return false
  }
}

async function commitAndPush(repoDir, highItems) {
  const titles = highItems.map(i => `- ${i.ruleId}: ${i.title.slice(0, 60)}`).join('\n')
  const msg = `feat(detection): auto-update from security research ${TODAY}\n\nSources:\n${highItems.map(i => `- ${i.source}: ${i.title.slice(0, 80)}`).join('\n')}\n\nNew rules:\n${titles}`

  await execAsync('git config user.email "monitor@shieldx.local"', { cwd: repoDir })
  await execAsync('git config user.name "ShieldX Monitor"', { cwd: repoDir })
  await execAsync('git add src/detection/AutoGeneratedRules.ts', { cwd: repoDir })

  const { stdout: status } = await execAsync('git status --short', { cwd: repoDir })
  if (!status.trim()) {
    log('No changes to commit')
    return false
  }

  await execAsync(`git commit -m "${msg.replace(/"/g, "'")}"`, { cwd: repoDir })
  await execAsync('git push origin main', { cwd: repoDir })
  log(`Committed and pushed ${highItems.length} new rules to Gitea`)
  return true
}

// ── Report ────────────────────────────────────────────────────────────────────

function saveReport(classified, committed) {
  const report = {
    date: TODAY,
    total_scanned: classified.length,
    high: classified.filter(i => i.level === 'HIGH'),
    medium: classified.filter(i => i.level === 'MEDIUM'),
    low: classified.filter(i => i.level === 'LOW'),
    skip: classified.filter(i => i.level === 'SKIP').length,
    committed,
  }

  const reportFile = join(LOG_DIR, `shieldx-report-${TODAY}.json`)
  writeFileSync(reportFile, JSON.stringify(report, null, 2))

  log(`\n=== ShieldX Daily Security Monitor — ${TODAY} ===`)
  log(`Total scanned: ${report.total_scanned}`)
  log(`HIGH findings: ${report.high.length}`)
  for (const h of report.high) log(`  → [HIGH] ${h.title.slice(0, 80)} (${h.ruleId})`)
  log(`MEDIUM findings: ${report.medium.length}`)
  for (const m of report.medium) log(`  → [MED] ${m.title.slice(0, 80)}`)
  log(`LOW/SKIP: ${report.low.length + report.skip}`)
  log(`Rules committed: ${committed ? 'YES' : 'NO'}`)
  log(`Report saved: ${reportFile}`)
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  log(`ShieldX arXiv Monitor starting — ${TODAY}`)

  if (!ANTHROPIC_API_KEY) {
    log('FATAL: ANTHROPIC_API_KEY not set. Add to /opt/scripts/.env')
    process.exit(1)
  }

  // 1. Fetch feeds
  const [csCR, csAI, hnItems] = await Promise.all([
    fetchArxiv('cs.CR'),
    fetchArxiv('cs.AI'),
    fetchHackerNews(),
  ])
  const allItems = [...csCR, ...csAI, ...hnItems]
  log(`Total items to classify: ${allItems.length}`)

  // 2. Classify via Claude Haiku
  const classified = await classifyItems(allItems)
  const highItems = classified.filter(i => i.level === 'HIGH')
  log(`Classification complete: ${highItems.length} HIGH, ${classified.filter(i=>i.level==='MEDIUM').length} MEDIUM`)

  // 3. For HIGH items: generate detection code
  let committed = false
  if (highItems.length > 0 && GITEA_TOKEN) {
    for (const item of highItems) {
      log(`Generating detection code for: ${item.title.slice(0, 60)}`)
      item.code = await generateDetectionCode(item)
    }

    const itemsWithCode = highItems.filter(i => i.code)
    if (itemsWithCode.length > 0) {
      try {
        const repoDir = await cloneOrPullShieldX()
        await appendToNewRulesFile(repoDir, itemsWithCode)
        const ok = await typecheck(repoDir)
        if (ok) {
          committed = await commitAndPush(repoDir, itemsWithCode)
        }
      } catch (e) {
        log(`ERROR: Git operations failed: ${e.message}`)
      }
    }
  } else if (highItems.length > 0 && !GITEA_TOKEN) {
    log('WARN: GITEA_TOKEN not set — HIGH findings detected but not committed')
  }

  // 4. Save report
  saveReport(classified, committed)
}

main().catch(e => {
  log(`FATAL: ${e.message}\n${e.stack}`)
  process.exit(1)
})
