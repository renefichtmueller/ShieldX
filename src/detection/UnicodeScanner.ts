/**
 * Unicode Scanner — ShieldX Layer 5
 *
 * Detects Unicode-based covert channels, ASCII smuggling, and
 * steganographic payloads in LLM input/output.
 *
 * Attack vectors covered:
 * - ASCII Smuggling via Unicode Tags Block (U+E0000–U+E007F)
 *   → FireTail Research Sep 2025, Embrace The Red, AWS Security Blog
 * - Variant Selector encoding (U+FE00–U+FE0F, U+E0100–U+E01EF)
 *   → Allows raw byte encoding using Extended ASCII mapping
 * - Zero-Width Characters as covert channel (ZWNJ U+200C, ZWJ U+200D)
 *   → Used for binary encoding (0/1 bit per invisible char)
 * - CamoLeak / Image-ordering exfiltration (CVE-2025-53773, GitHub Copilot)
 *   → 100 × 1px images in sequence encode data without URL parameters
 * - EchoLeak markdown reference-style auto-fetch (CVE-2025-32711, CVSS 9.3)
 * - High-entropy base64 blobs in URL query parameters (exfiltration channel)
 * - Homoglyph substitution (Cyrillic/Greek visually matching ASCII)
 * - Directional override characters (RLO/LRO — filename spoofing)
 *
 * MITRE ATLAS: AML.T0043 (Adversarial Inputs / Obfuscated Payloads)
 *              AML.T0051 (LLM Prompt Injection — invisible variant)
 * OWASP LLM: LLM01:2025 (Prompt Injection), LLM02:2025 (Information Disclosure)
 */

import type { ScanResult, KillChainPhase, ThreatLevel } from '../types/detection'

/** Helper to build a properly-shaped ScanResult */
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
    scannerType: 'unicode',
    detected: true,
    confidence,
    threatLevel,
    killChainPhase: phase,
    matchedPatterns: [matchedText.substring(0, 120)],
    latencyMs,
    metadata: { description, matchedText: matchedText.substring(0, 200) },
  }
}

// ── Unicode Tags Block (ASCII Smuggling) ─────────────────────────────────────

/**
 * Unicode Tags Block: U+E0000–U+E007F
 * Each character in this range shadows ASCII (U+E0061 = invisible 'a', etc.)
 * Used to embed hidden instructions invisible in most UIs.
 * Reference: AWS Security Blog "Defending against Unicode Character Smuggling"
 */
const TAGS_BLOCK_START = 0xe0000
const TAGS_BLOCK_END = 0xe007f

function detectTagsBlock(text: string): { found: boolean; decoded: string; count: number } {
  let decoded = ''
  let count = 0
  for (const char of text) {
    const cp = char.codePointAt(0) ?? 0
    if (cp >= TAGS_BLOCK_START && cp <= TAGS_BLOCK_END) {
      const ascii = cp - TAGS_BLOCK_START
      if (ascii >= 0x20 && ascii <= 0x7e) {
        decoded += String.fromCharCode(ascii)
      }
      count++
    }
  }
  return { found: count > 0, decoded, count }
}

// ── Variant Selectors (Extended ASCII encoding) ───────────────────────────────

/**
 * Variant Selectors U+FE00–U+FE0F (VS1–VS16) and
 * Variation Selectors Supplement U+E0100–U+E01EF (VS17–VS256)
 * Outside valid emoji contexts, these can encode arbitrary bytes.
 */
function detectVariantSelectors(text: string): number {
  let count = 0
  // Non-emoji context detection: count VS chars not preceded by emoji base
  const chars = [...text]
  for (let i = 0; i < chars.length; i++) {
    const cp = (chars[i] ?? '').codePointAt(0) ?? 0
    const isVS1_16 = cp >= 0xfe00 && cp <= 0xfe0f
    const isVSS = cp >= 0xe0100 && cp <= 0xe01ef
    if (isVS1_16 || isVSS) {
      // Check if preceded by valid emoji base (simplified: emoji range U+1F300+)
      const prevChar = i > 0 ? (chars[i - 1] ?? '') : ''
      const prevCp = prevChar.codePointAt(0) ?? 0
      const isAfterEmoji = prevCp >= 0x1f300
      if (!isAfterEmoji) count++
    }
  }
  return count
}

// ── Zero-Width Characters ─────────────────────────────────────────────────────

/**
 * Zero-width characters used for binary steganography:
 * - U+200B ZERO WIDTH SPACE
 * - U+200C ZERO WIDTH NON-JOINER
 * - U+200D ZERO WIDTH JOINER
 * - U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM in middle of text)
 * - U+2060 WORD JOINER
 */
const ZERO_WIDTH_CHARS = new Set([0x200b, 0x200c, 0x200d, 0xfeff, 0x2060, 0x180e, 0x00ad])

function detectZeroWidth(text: string): { count: number; types: string[] } {
  const found = new Map<number, number>()
  for (const char of text) {
    const cp = char.codePointAt(0) ?? 0
    if (ZERO_WIDTH_CHARS.has(cp)) {
      found.set(cp, (found.get(cp) ?? 0) + 1)
    }
  }
  const types = [...found.entries()].map(([cp, n]) => `U+${cp.toString(16).toUpperCase().padStart(4, '0')}×${n}`)
  return { count: [...found.values()].reduce((a, b) => a + b, 0), types }
}

// ── Directional Override Characters ──────────────────────────────────────────

/**
 * Bidirectional control characters used for filename/content spoofing:
 * - U+202E RIGHT-TO-LEFT OVERRIDE (RLO) — classic filename spoof
 * - U+202D LEFT-TO-RIGHT OVERRIDE (LRO)
 * - U+2066–U+2069 Isolate characters
 */
function detectDirectionalOverride(text: string): boolean {
  const BIDIR_OVERRIDES = [0x202e, 0x202d, 0x2066, 0x2067, 0x2068, 0x2069, 0x200f, 0x200e]
  for (const char of text) {
    const cp = char.codePointAt(0) ?? 0
    if (BIDIR_OVERRIDES.includes(cp)) return true
  }
  return false
}

// ── Homoglyph Detection ───────────────────────────────────────────────────────

/**
 * Common homoglyph substitutions used to evade keyword-based filters.
 * Maps confusable Unicode chars to their ASCII equivalents.
 * Reference: Unicode Confusables (https://www.unicode.org/reports/tr39/)
 */
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic → Latin
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
  'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
  // Greek → Latin
  'α': 'a', 'ε': 'e', 'ι': 'i', 'ο': 'o', 'ν': 'v', 'κ': 'k',
  // Fullwidth Latin
  'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e',
  // Mathematical variants
  '𝒊': 'i', '𝒏': 'n', '𝒔': 's', '𝒕': 't', '𝒓': 'r', '𝒖': 'u', '𝒄': 'c',
  // Superscript/subscript
  'ⁱ': 'i', 'ⁿ': 'n',
}

function normalizeHomoglyphs(text: string): { normalized: string; substitutions: number } {
  let substitutions = 0
  let normalized = ''
  for (const char of text) {
    if (HOMOGLYPH_MAP[char]) {
      normalized += HOMOGLYPH_MAP[char]
      substitutions++
    } else {
      normalized += char
    }
  }
  return { normalized, substitutions }
}

// ── CamoLeak: Image-Ordering Exfiltration (CVE-2025-53773) ──────────────────

/**
 * CamoLeak attack: encodes data in the SEQUENCE of ~100 1×1 pixel image requests.
 * Each image URL maps to a specific character/symbol.
 * Data is in the order of fetches, not URL parameters — bypasses CSP entirely.
 *
 * Detection heuristic:
 * - Multiple markdown/HTML image references to the same domain
 * - Images are 1×1 or very small (in URL path/params: size=1, w=1, h=1)
 * - Sequential identifiers in URLs (id=1, id=2 ... id=100)
 * - Same external CDN/proxy used repeatedly
 */
function detectCamoLeak(text: string): ScanResult[] {
  const results: ScanResult[] = []

  // Pattern 1: Many images to same domain (>5)
  const imgUrlPattern = /!\[.*?\]\(?(https?:\/\/([^)\s"']+))/g
  const domains = new Map<string, number>()
  let m: RegExpExecArray | null
  while ((m = imgUrlPattern.exec(text)) !== null) {
    const domainPart = m[2]?.split('/')[0] ?? ''
    if (domainPart) domains.set(domainPart, (domains.get(domainPart) ?? 0) + 1)
  }

  for (const [domainName, count] of domains.entries()) {
    if (count >= 5) {
      results.push(makeResult(
        'unicode-camoleak-001', 'actions_on_objective', 0.88, 'high',
        `CamoLeak pattern: ${count} image requests to "${domainName}" — ordering-based exfiltration (CVE-2025-53773)`,
        `[img:${domainName}×${count}]`, 0,
      ))
    }
  }

  // Pattern 2: Sequential image IDs (id=1...N or /1.png, /2.png...)
  const seqPattern = /https?:\/\/[^\s]+?(?:\/(\d+)\.|[?&](?:id|n|seq|i)=(\d+))/g
  const seqNums: number[] = []
  while ((m = seqPattern.exec(text)) !== null) {
    const raw = m[1] ?? m[2]
    const num = raw !== undefined ? parseInt(raw, 10) : 0
    if (num > 0) seqNums.push(num)
  }
  if (seqNums.length >= 8) {
    const sorted = [...seqNums].sort((a, b) => a - b)
    const first = sorted[0] ?? 0
    const last = sorted[sorted.length - 1] ?? 0
    const isSequential = last - first === sorted.length - 1
    if (isSequential) {
      results.push(makeResult(
        'unicode-camoleak-002', 'actions_on_objective', 0.93, 'critical',
        `Sequential image IDs detected (${first}–${last}, n=${seqNums.length}) — CamoLeak ordering exfiltration signature`,
        `seq:${first}-${last}`, 0,
      ))
    }
  }

  return results
}

// ── High-Entropy URL Parameters (Exfiltration Channel) ───────────────────────

function detectEncodedUrlParams(text: string): ScanResult[] {
  const results: ScanResult[] = []
  // Find URL query parameters with long base64/URL-encoded values
  const paramPattern = /[?&]([a-zA-Z0-9_-]{1,20})=([A-Za-z0-9+/=_%-]{24,})/g
  let m: RegExpExecArray | null
  while ((m = paramPattern.exec(text)) !== null) {
    const paramKey = m[1] ?? ''
    const paramVal = m[2] ?? ''
    if (!paramVal) continue
    // Check entropy
    const freq: Record<string, number> = {}
    for (const ch of paramVal) freq[ch] = (freq[ch] ?? 0) + 1
    let entropy = 0
    for (const count of Object.values(freq)) {
      const p = count / paramVal.length
      entropy -= p * Math.log2(p)
    }
    if (entropy >= 4.0 && paramVal.length >= 24) {
      results.push(makeResult(
        'unicode-url-exfil-001', 'actions_on_objective', 0.78, 'high',
        `High-entropy URL parameter "${paramKey}=" (H=${entropy.toFixed(2)}, len=${paramVal.length}) — possible data exfiltration channel`,
        m[0].substring(0, 60), 0,
      ))
    }
  }
  return results
}

// ── Main Scanner ──────────────────────────────────────────────────────────────

export function scanUnicode(input: string): ScanResult[] {
  const results: ScanResult[] = []
  const start = performance.now()

  // 1) Unicode Tags Block — ASCII Smuggling (highest priority)
  const tags = detectTagsBlock(input)
  if (tags.found) {
    const hiddenText = tags.decoded.substring(0, 80)
    const threat: ThreatLevel = tags.count > 10 ? 'critical' : 'high'
    results.push(makeResult(
      'unicode-tags-001', 'initial_access', 0.97, threat,
      `Unicode Tags Block ASCII Smuggling: ${tags.count} invisible chars detected. Decoded hidden payload: "${hiddenText}"`,
      `[${tags.count} Tags Block chars] → "${hiddenText}"`,
      performance.now() - start,
    ))
  }

  // 2) Variant Selectors (out-of-emoji-context)
  const vsCount = detectVariantSelectors(input)
  if (vsCount >= 3) {
    results.push(makeResult(
      'unicode-vs-001', 'initial_access', 0.85, vsCount >= 10 ? 'critical' : 'high',
      `Variant Selector encoding: ${vsCount} suspicious VS chars outside emoji context — possible byte-level steganography`,
      `[${vsCount} Variant Selectors]`,
      performance.now() - start,
    ))
  }

  // 3) Zero-Width Characters
  const zw = detectZeroWidth(input)
  if (zw.count >= 4) {
    // Minimum 4 for binary encoding to be meaningful (2 bits)
    const threat: ThreatLevel = zw.count >= 20 ? 'high' : 'medium'
    results.push(makeResult(
      'unicode-zw-001', 'initial_access', 0.75, threat,
      `Zero-width character steganography: ${zw.count} chars (${zw.types.join(', ')}) — binary bit-channel (ZWNJ=0, ZWJ=1)`,
      `[ZW: ${zw.types.join(', ')}]`,
      performance.now() - start,
    ))
  }

  // 4) Directional Override — content spoofing
  if (detectDirectionalOverride(input)) {
    results.push(makeResult(
      'unicode-bidi-001', 'initial_access', 0.91, 'high',
      'Bidirectional override character (RLO/LRO U+202E/202D) — filename spoofing or content reversal attack',
      '[BiDi Override]',
      performance.now() - start,
    ))
  }

  // 5) Homoglyph substitution
  const { normalized, substitutions } = normalizeHomoglyphs(input)
  if (substitutions >= 3) {
    // Check if normalization changes threat detection — e.g. keyword appears after normalize
    const SUSPICIOUS_KEYWORDS = ['ignore', 'system', 'prompt', 'forget', 'jailbreak', 'override', 'admin', 'root']
    const lowerNorm = normalized.toLowerCase()
    const matchedKw = SUSPICIOUS_KEYWORDS.filter(kw => lowerNorm.includes(kw))
    const threat: ThreatLevel = matchedKw.length > 0 ? 'critical' : 'medium'
    const confidence = matchedKw.length > 0 ? 0.92 : 0.65

    if (threat === 'critical' || substitutions >= 8) {
      results.push(makeResult(
        'unicode-homoglyph-001', 'initial_access', confidence, threat,
        `Homoglyph substitution: ${substitutions} confusable chars${matchedKw.length > 0 ? `. After normalization matches: [${matchedKw.join(', ')}]` : ''}`,
        `[${substitutions} homoglyphs${matchedKw.length > 0 ? ` → "${matchedKw[0]}"` : ''}]`,
        performance.now() - start,
      ))
    }
  }

  // 6) CamoLeak / image-ordering exfiltration
  const camoResults = detectCamoLeak(input)
  for (const r of camoResults) {
    results.push({ ...r, latencyMs: performance.now() - start })
  }

  // 7) High-entropy URL parameters
  const urlResults = detectEncodedUrlParams(input)
  for (const r of urlResults) {
    results.push({ ...r, latencyMs: performance.now() - start })
  }

  return results
}

/**
 * Sanitize a string by removing or replacing dangerous Unicode characters.
 * Used by the self-healing layer when unicode attack is detected.
 */
export function sanitizeUnicode(input: string): string {
  let result = ''
  for (const char of input) {
    const cp = char.codePointAt(0) ?? 0
    // Remove Tags Block
    if (cp >= TAGS_BLOCK_START && cp <= TAGS_BLOCK_END) continue
    // Remove variant selectors outside emoji context (simplified: always remove)
    if ((cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef)) continue
    // Remove zero-width chars
    if (ZERO_WIDTH_CHARS.has(cp)) continue
    // Remove bidi overrides
    if ([0x202e, 0x202d, 0x2066, 0x2067, 0x2068, 0x2069, 0x200f, 0x200e].includes(cp)) continue
    // Normalize homoglyphs
    result += HOMOGLYPH_MAP[char] ?? char
  }
  return result
}

/** UnicodeScanner class — drop-in for the L5 stub in ShieldX.ts */
export class UnicodeScanner {
  scan(input: string): ScanResult[] {
    return scanUnicode(input)
  }

  sanitize(input: string): string {
    return sanitizeUnicode(input)
  }
}
