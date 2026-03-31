/**
 * Entropy Scanner — ShieldX Layer 4
 *
 * Statistical analysis for detecting encoded/obfuscated payloads and
 * DNS covert-channel indicators in LLM input/output.
 *
 * Thresholds are based on empirical research:
 * - arXiv:2507.10267 "DNS Sentinel": entropy + length features, 1.00 recall
 * - arXiv:2410.21723: LLM-based DNS exfil detection, 59 DGA families
 * - Check Point Research Feb 2026: ChatGPT DNS exfil (Base32/Base64url encoding)
 * - CVE-2025-55284: Claude Code DNS exfil via whitelisted `ping` (CVSS 7.1)
 * - iodine/dnscat2 detection research (Shannon entropy > 4.0 for DNS labels)
 *
 * Reference thresholds (DNS tunneling research):
 *   Normal hostname entropy:  H ≈ 2.5–3.5 bits/char
 *   Base32 encoded label:     H ≈ 4.0–4.5 bits/char  ← detection threshold
 *   Random/encrypted label:   H ≈ 5.0–6.0 bits/char
 *   Normal label length:      avg 6–12 chars
 *   Tunneling label length:   typically >= 32 chars, often 50–63 chars
 *
 * MITRE ATLAS: AML.T0025 (Exfiltration via Cyber Means)
 *              AML.T0051 (LLM Prompt Injection → DNS tool abuse)
 */

import type { ScanResult, KillChainPhase, ThreatLevel } from '../types/detection'

/** Helper to build a properly-shaped ScanResult for the orchestrator */
function makeResult(
  ruleId: string,
  phase: KillChainPhase,
  confidence: number,
  threatLevel: ThreatLevel,
  description: string,
  matchedText: string,
  latencyMs: number,
): ScanResult {
  return {
    scannerId: ruleId,
    scannerType: 'entropy',
    detected: true,
    confidence,
    threatLevel,
    killChainPhase: phase,
    matchedPatterns: [matchedText.substring(0, 120)],
    latencyMs,
    metadata: { description, matchedText: matchedText.substring(0, 200) },
  }
}

export interface EntropyResult {
  /** Shannon entropy value (0 = uniform, ~4.7 = random/encrypted) */
  entropy: number
  /** True if entropy exceeds the suspicious threshold */
  suspicious: boolean
  /** Reason for flagging */
  reason?: string
  /** The suspicious token that was analysed */
  token?: string
}

// ── Detection Thresholds (research-backed) ──────────────────────────────────

const ENTROPY_THRESHOLD_DNS = 4.0          // Base32/Base64 DNS labels exceed this
const ENTROPY_THRESHOLD_STRICT = 3.8       // Stricter, with length confirmation
const LABEL_LENGTH_SUSPICIOUS = 32         // Labels 32+ chars are unusual
const LABEL_LENGTH_TUNNELING = 50          // 50+ chars = strong tunneling indicator (63 max)
const BURST_QUERY_THRESHOLD = 3            // 3+ DNS queries in one prompt = burst pattern
const BASE64_DENSITY_THRESHOLD = 0.92     // >92% base64 charset chars
const BASE32_CHARSET = /^[A-Z2-7=]+$/     // RFC 4648 Base32 (iodine/DNSExfiltrator default)
const BASE64URL_CHARSET = /^[A-Za-z0-9_-]+$/ // URL-safe Base64 (AWS AgentCore variant)

// ── Shannon Entropy ───────────────────────────────────────────────────────

/**
 * Shannon entropy: H = -Σ p(x) * log2(p(x))
 * Normal English: H ≈ 3.0–3.5 | Base64: H ≈ 4.0–4.5 | Random: H ≈ 5.0–6.0
 */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0
  const freq: Record<string, number> = {}
  for (const ch of s) {
    freq[ch] = (freq[ch] ?? 0) + 1
  }
  let h = 0
  for (const count of Object.values(freq)) {
    const p = count / s.length
    h -= p * Math.log2(p)
  }
  return h
}

// ── DNS Label Analysis ────────────────────────────────────────────────────

/** Analyse a single DNS label for data encoding indicators */
function analyseLabel(label: string): EntropyResult {
  const entropy = shannonEntropy(label)
  const len = label.length
  const upper = label.toUpperCase()

  // Base32 exact match (RFC 4648, used by iodine, DNSExfiltrator)
  // Charset: A-Z + 2-7 + optional = padding
  if (len >= 16 && BASE32_CHARSET.test(upper) && entropy >= ENTROPY_THRESHOLD_STRICT) {
    return {
      entropy, suspicious: true,
      reason: `Base32-encoded label (iodine/DNSExfiltrator pattern, H=${entropy.toFixed(2)}, len=${len})`,
      token: label,
    }
  }

  // Base64url (AWS AgentCore variant, URL-safe alphabet)
  if (len >= 20 && BASE64URL_CHARSET.test(label) && entropy >= ENTROPY_THRESHOLD_DNS) {
    return {
      entropy, suspicious: true,
      reason: `Base64url-encoded label (H=${entropy.toFixed(2)}, len=${len})`,
      token: label,
    }
  }

  // Strong length + entropy combined (tunneling tools use 50–63 char labels)
  if (len >= LABEL_LENGTH_TUNNELING && entropy >= ENTROPY_THRESHOLD_STRICT) {
    return {
      entropy, suspicious: true,
      reason: `Very long high-entropy label — DNS tunneling (H=${entropy.toFixed(2)}, len=${len})`,
      token: label,
    }
  }

  // Medium: long label with high entropy
  if (len >= LABEL_LENGTH_SUSPICIOUS && entropy >= ENTROPY_THRESHOLD_DNS) {
    return {
      entropy, suspicious: true,
      reason: `Long high-entropy DNS label — data encoding (H=${entropy.toFixed(2)}, len=${len})`,
      token: label,
    }
  }

  // Base64 density check: >92% base64 charset
  const b64Chars = label.replace(/[^A-Za-z0-9+/=_-]/g, '').length
  if (len >= 20 && b64Chars / len > BASE64_DENSITY_THRESHOLD && entropy >= ENTROPY_THRESHOLD_STRICT) {
    return {
      entropy, suspicious: true,
      reason: `High base64-char density (${((b64Chars / len) * 100).toFixed(0)}%) — encoded subdomain`,
      token: label,
    }
  }

  return { entropy, suspicious: false }
}

// ── Sequential Chunk Pattern (p001_, p002_ reassembly markers) ────────────

function detectChunkingPatterns(text: string): string[] {
  // New regex each call to avoid global lastIndex state issues
  const pattern = /\b(p\d{2,3}[_.]|chunk\d+[_.]|c\d+[_.])([A-Za-z0-9+/=_-]{6,})\./gi
  const matches: string[] = []
  let m: RegExpExecArray | null
  while ((m = pattern.exec(text)) !== null) {
    matches.push(m[0])
  }
  return matches
}

// ── Domain Extraction ─────────────────────────────────────────────────────

function extractDomainPatterns(text: string): Array<{ domain: string; labels: string[] }> {
  // Match URLs and standalone FQDNs with at least 3 labels
  const domainRx = /(?:https?:\/\/)?([a-zA-Z0-9._-]{12,}\.(?:com|net|org|io|xyz|app|dev|ai|co|info|biz|me|us|[a-z]{2,4}))(?:[/?][^\s]*)?/g
  const results: Array<{ domain: string; labels: string[] }> = []
  let m: RegExpExecArray | null
  while ((m = domainRx.exec(text)) !== null) {
    const domain = m[1] ?? ''
    if (!domain) continue
    const parts = domain.split('.')
    if (parts.length >= 3) {
      const labels = parts.slice(0, -2) // everything before SLD + TLD
      if (labels.some(l => l.length >= 12)) {
        results.push({ domain, labels })
      }
    }
  }
  return results
}

// ── High-Entropy Token Scan ───────────────────────────────────────────────

function analyseHighEntropyTokens(text: string): EntropyResult[] {
  const results: EntropyResult[] = []
  const tokens = text.split(/[\s,;|"'`\[\]{}()<>\n]+/).filter(t => t.length >= 16)

  for (const token of tokens) {
    const entropy = shannonEntropy(token)
    // Base64 blob: long, high entropy, correct charset
    if (/^[A-Za-z0-9+/=_-]+$/.test(token) && entropy >= 4.2 && token.length >= 24) {
      results.push({ entropy, suspicious: true, reason: 'High-entropy Base64 payload blob', token })
    }
    // Hex blob: long hex string (>= 32 chars = 16 bytes)
    else if (/^[0-9a-fA-F]+$/.test(token) && token.length >= 32 && entropy >= 3.2) {
      results.push({ entropy, suspicious: true, reason: 'Long hex-encoded payload', token })
    }
  }
  return results
}

// ── CVE-2025-55284 Pattern: ping/nslookup with encoded hostname ───────────

// Note: do NOT define global /g regex at module scope — create new instances per call

function detectToolExfiltration(text: string): ScanResult[] {
  const results: ScanResult[] = []
  const TOOL_EXFIL_PATTERN = /(?:ping|nslookup|host|dig)\s+([a-zA-Z0-9._-]{20,})/gi
  let m: RegExpExecArray | null
  while ((m = TOOL_EXFIL_PATTERN.exec(text)) !== null) {
    const hostname = m[1] ?? ''
    if (!hostname) continue
    const labels = hostname.split('.')
    const suspiciousLabels = labels.filter(l => l.length > 20)
    if (suspiciousLabels.length > 0) {
      const entropy = shannonEntropy(suspiciousLabels[0] ?? '')
      if (entropy >= ENTROPY_THRESHOLD_STRICT) {
        results.push(makeResult('entropy-cve-55284', 'actions_on_objective', 0.94, 'critical',
          `CVE-2025-55284: ${m[0].split(' ')[0]} with encoded hostname (H=${entropy.toFixed(2)}) — whitelisted tool DNS exfiltration`,
          m[0].substring(0, 80), 0))
      }
    }
  }
  return results
}

// ── EchoLeak Pattern: Markdown image exfiltration ─────────────────────────

function detectMarkdownExfiltration(text: string): ScanResult[] {
  const MARKDOWN_EXFIL_PATTERN = /!\[.*?\]\s*\[.*?\][\s\S]*?\[.*?\]:\s*https?:\/\/[^\s]+(?:[?&][a-zA-Z0-9+/=_-]{16,})/gi
  const matched = text.match(MARKDOWN_EXFIL_PATTERN)
  if (!matched) return []
  return [makeResult('entropy-echoleak', 'actions_on_objective', 0.91, 'high',
    'EchoLeak/CVE-2025-32711: Markdown reference-style image with encoded URL — auto-fetch exfiltration',
    matched[0].substring(0, 80), 0)]
}

// ── Main Scanner ──────────────────────────────────────────────────────────

export function scanEntropy(input: string): ScanResult[] {
  const results: ScanResult[] = []
  const start = performance.now()

  // 1) DNS subdomain label entropy analysis
  const domains = extractDomainPatterns(input)
  for (const { domain, labels } of domains) {
    for (const label of labels) {
      const r = analyseLabel(label)
      if (r.suspicious) {
        results.push(makeResult('entropy-dns-001', 'actions_on_objective', 0.87, 'high',
          `DNS label entropy: ${r.reason} in domain "${domain}"`, domain, performance.now() - start))
      }
    }
  }

  // 2) Multi-label chunked exfiltration (2+ suspicious labels = critical)
  for (const { domain, labels } of domains) {
    const suspiciousCount = labels.filter(l => analyseLabel(l).suspicious).length
    if (suspiciousCount >= 2) {
      results.push(makeResult('entropy-dns-002', 'actions_on_objective', 0.95, 'critical',
        `DNS multi-label exfil: ${suspiciousCount} high-entropy labels in "${domain}" — chunked exfiltration (dnscat2/iodine)`,
        domain, performance.now() - start))
    }
  }

  // 3) Sequential chunk markers (p001_, p002_ reassembly pattern)
  const chunks = detectChunkingPatterns(input)
  if (chunks.length >= 2) {
    results.push(makeResult('entropy-dns-003', 'actions_on_objective', 0.97, 'critical',
      `DNS sequential chunking: ${chunks.length} chunk markers (p001_/p002_) — DNSExfiltrator reassembly signature`,
      chunks.slice(0, 3).join(', '), performance.now() - start))
  }

  // 4) DNS query burst (3+ queries in prompt = automated exfil loop)
  const dnsQueriesRx = /(?:nslookup|dig|socket\.gethostbyname|resolve|dns(?:lookup|query)?)\s+([a-zA-Z0-9._-]+)/gi
  const dnsQueries: string[] = []
  {
    let m: RegExpExecArray | null
    while ((m = dnsQueriesRx.exec(input)) !== null) { const q = m[1]; if (q) dnsQueries.push(q) }
  }
  if (dnsQueries.length >= BURST_QUERY_THRESHOLD) {
    results.push(makeResult('entropy-dns-004', 'command_and_control', 0.90, 'high',
      `DNS query burst: ${dnsQueries.length} queries — C2 beaconing or automated exfiltration loop`,
      dnsQueries.slice(0, 3).join(', '), performance.now() - start))
  }

  // 5) CVE-2025-55284: ping/nslookup with encoded hostname
  const toolResults = detectToolExfiltration(input)
  results.push(...toolResults)

  // 6) EchoLeak Markdown image exfiltration
  const echoResults = detectMarkdownExfiltration(input)
  results.push(...echoResults)

  // 7) General high-entropy token scan
  const tokenResults = analyseHighEntropyTokens(input)
  for (const tr of tokenResults.slice(0, 3)) {
    results.push(makeResult('entropy-payload-001', 'actions_on_objective', 0.72, 'medium',
      `High-entropy payload: ${tr.reason} (H=${tr.entropy.toFixed(2)}, len=${tr.token?.length})`,
      tr.token?.substring(0, 40) ?? '', performance.now() - start))
  }

  return results
}

/** EntropyScanner class — drop-in for the L4 stub in ShieldX.ts */
export class EntropyScanner {
  scan(input: string): ScanResult[] {
    return scanEntropy(input)
  }
}
