/**
 * ShieldX Ollama Protection Proxy
 *
 * A zero-dependency HTTP proxy that sits between clients and Ollama,
 * scanning every prompt with the ShieldX rule engine before forwarding.
 *
 * Architecture:  Clients --> :11435 (this proxy) --> :11434 (Ollama)
 *
 * Environment variables:
 *   PORT             — Proxy listen port (default: 11435)
 *   OLLAMA_ENDPOINT  — Upstream Ollama URL (default: http://localhost:11434)
 *   SHIELDX_MODE     — "block" | "warn" | "passthrough" (default: block)
 */

import { createServer, request as httpRequest } from 'node:http'
import { URL } from 'node:url'
import { scan, getRuleCount } from './scanner.js'

// ---------------------------------------------------------------------------
// Configuration (immutable after startup)
// ---------------------------------------------------------------------------
const PORT = parseInt(process.env.PORT || '11435', 10)
const OLLAMA_ENDPOINT = process.env.OLLAMA_ENDPOINT || 'http://localhost:11434'
const SHIELDX_MODE = process.env.SHIELDX_MODE || 'block'
const ollamaUrl = new URL(OLLAMA_ENDPOINT)

// ---------------------------------------------------------------------------
// ANSI colour helpers
// ---------------------------------------------------------------------------
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
}

// ---------------------------------------------------------------------------
// Statistics (mutable counters)
// ---------------------------------------------------------------------------
let stats = { total: 0, scanned: 0, blocked: 0, warned: 0, sanitized: 0, clean: 0 }

// ---------------------------------------------------------------------------
// Utility: read full request body as buffer
// ---------------------------------------------------------------------------
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    req.on('data', (chunk) => chunks.push(chunk))
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

// ---------------------------------------------------------------------------
// Utility: extract user message from Ollama request body
// ---------------------------------------------------------------------------
function extractUserMessage(path, body) {
  try {
    const json = JSON.parse(body.toString('utf-8'))

    if (path === '/api/chat' && Array.isArray(json.messages)) {
      // Get the last user message
      const userMessages = json.messages.filter((m) => m.role === 'user')
      const lastUser = userMessages[userMessages.length - 1]
      return { text: lastUser?.content || '', json, field: 'messages' }
    }

    if (path === '/api/generate' && typeof json.prompt === 'string') {
      return { text: json.prompt, json, field: 'prompt' }
    }

    return null
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// Utility: replace user message in parsed body and return new buffer
// ---------------------------------------------------------------------------
function replaceUserMessage(path, parsed, newText) {
  if (path === '/api/chat' && Array.isArray(parsed.messages)) {
    const updated = {
      ...parsed,
      messages: parsed.messages.map((m, i, arr) => {
        // Replace last user message
        const isLastUser =
          m.role === 'user' &&
          arr.slice(i + 1).every((n) => n.role !== 'user')
        return isLastUser ? { ...m, content: newText } : m
      }),
    }
    return Buffer.from(JSON.stringify(updated), 'utf-8')
  }

  if (path === '/api/generate') {
    const updated = { ...parsed, prompt: newText }
    return Buffer.from(JSON.stringify(updated), 'utf-8')
  }

  return null
}

// ---------------------------------------------------------------------------
// Utility: format timestamp
// ---------------------------------------------------------------------------
function ts() {
  return new Date().toISOString().replace('T', ' ').slice(0, 19)
}

// ---------------------------------------------------------------------------
// Log a scan result to console
// ---------------------------------------------------------------------------
function logScan(method, path, result, latencyTotal) {
  const { action, threatLevel, confidence, matches, metadata } = result
  const scanMs = result.latencyMs.toFixed(1)
  const totalMs = latencyTotal.toFixed(1)

  if (!result.detected) {
    console.log(
      `${C.dim}[${ts()}]${C.reset} ${C.green}CLEAN${C.reset}  ${method} ${path}  ` +
      `${C.dim}scan=${scanMs}ms  rules=${metadata.ruleCount}  len=${metadata.inputLength}${C.reset}`
    )
    return
  }

  const colorMap = {
    block: C.bgRed + C.white,
    incident: C.bgRed + C.white,
    sanitize: C.bgYellow + C.white,
    warn: C.yellow,
    allow: C.green,
  }
  const badge = colorMap[action] || C.white

  console.log(
    `${C.dim}[${ts()}]${C.reset} ${badge} ${action.toUpperCase()} ${C.reset} ` +
    `${method} ${path}  ` +
    `${C.bold}threat=${threatLevel}${C.reset}  ` +
    `conf=${(confidence * 100).toFixed(0)}%  ` +
    `matches=${matches.length}  ` +
    `scan=${scanMs}ms  total=${totalMs}ms`
  )

  for (const m of matches.slice(0, 5)) {
    console.log(
      `  ${C.dim}|${C.reset} ${C.red}${m.ruleId}${C.reset} [${m.phase}] ${m.description}`
    )
  }
  if (matches.length > 5) {
    console.log(`  ${C.dim}| ... and ${matches.length - 5} more${C.reset}`)
  }
}

// ---------------------------------------------------------------------------
// Proxy a request to Ollama (streaming-safe)
// ---------------------------------------------------------------------------
function proxyToOllama(clientReq, clientRes, bodyOverride, shieldxHeaders) {
  const reqOptions = {
    hostname: ollamaUrl.hostname,
    port: ollamaUrl.port || 11434,
    path: clientReq.url,
    method: clientReq.method,
    headers: { ...clientReq.headers },
  }

  // Remove host header so Ollama gets the right one
  delete reqOptions.headers.host

  if (bodyOverride) {
    reqOptions.headers['content-length'] = Buffer.byteLength(bodyOverride)
  }

  const proxyReq = httpRequest(reqOptions, (proxyRes) => {
    // Copy response headers from Ollama
    const headers = { ...proxyRes.headers }

    // Add ShieldX headers
    if (shieldxHeaders) {
      for (const [k, v] of Object.entries(shieldxHeaders)) {
        headers[k] = v
      }
    }

    clientRes.writeHead(proxyRes.statusCode, headers)
    // Pipe the response directly (supports streaming)
    proxyRes.pipe(clientRes, { end: true })
  })

  proxyReq.on('error', (err) => {
    console.error(`${C.red}[PROXY ERROR]${C.reset} ${err.message}`)
    if (!clientRes.headersSent) {
      clientRes.writeHead(502, { 'Content-Type': 'application/json' })
    }
    clientRes.end(JSON.stringify({
      error: 'shieldx_proxy_error',
      message: `Failed to connect to Ollama at ${OLLAMA_ENDPOINT}: ${err.message}`,
    }))
  })

  if (bodyOverride) {
    proxyReq.end(bodyOverride)
  } else {
    clientReq.pipe(proxyReq, { end: true })
  }
}

// ---------------------------------------------------------------------------
// Main request handler
// ---------------------------------------------------------------------------
async function handleRequest(req, res) {
  const startTime = performance.now()
  stats.total++

  const method = req.method
  const path = req.url

  // Only scan POST to /api/chat and /api/generate
  const shouldScan =
    method === 'POST' &&
    (path === '/api/chat' || path === '/api/generate')

  if (!shouldScan) {
    // Transparent passthrough for everything else
    proxyToOllama(req, res, null, { 'X-ShieldX-Scanned': 'false' })
    return
  }

  // Read body for scanning
  let body
  try {
    body = await readBody(req)
  } catch (err) {
    res.writeHead(400, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'shieldx_read_error', message: err.message }))
    return
  }

  // Extract user message
  const extracted = extractUserMessage(path, body)

  if (!extracted || !extracted.text) {
    // No user message found — pass through unchanged
    proxyToOllama(req, res, body, { 'X-ShieldX-Scanned': 'false' })
    return
  }

  // Run ShieldX scan
  stats.scanned++
  const result = scan(extracted.text)
  const totalLatency = performance.now() - startTime

  // Build ShieldX response headers
  const shieldxHeaders = {
    'X-ShieldX-Scanned': 'true',
    'X-ShieldX-Detected': String(result.detected),
    'X-ShieldX-Threat-Level': result.threatLevel,
    'X-ShieldX-Action': result.action,
    'X-ShieldX-Confidence': result.confidence.toFixed(2),
    'X-ShieldX-Scan-Ms': result.latencyMs.toFixed(1),
    'X-ShieldX-Kill-Chain': result.killChainPhase,
    'X-ShieldX-Rules-Matched': String(result.matches.length),
  }

  logScan(method, path, result, totalLatency)

  // Decide what to do based on action
  const effectiveAction = SHIELDX_MODE === 'passthrough' ? 'allow' : result.action

  switch (effectiveAction) {
    case 'block':
    case 'incident': {
      stats.blocked++
      res.writeHead(403, {
        'Content-Type': 'application/json',
        ...shieldxHeaders,
      })
      res.end(JSON.stringify({
        error: 'shieldx_blocked',
        message: 'Request blocked by ShieldX: prompt injection detected',
        threatLevel: result.threatLevel,
        killChainPhase: result.killChainPhase,
        confidence: result.confidence,
        matchCount: result.matches.length,
        topRule: result.matches[0]?.ruleId || null,
        topDescription: result.matches[0]?.description || null,
      }))
      return
    }

    case 'sanitize': {
      stats.sanitized++
      if (result.sanitizedInput) {
        const newBody = replaceUserMessage(path, extracted.json, result.sanitizedInput)
        if (newBody) {
          proxyToOllama(req, res, newBody, shieldxHeaders)
          return
        }
      }
      // Fallback: forward original if sanitization failed
      proxyToOllama(req, res, body, shieldxHeaders)
      return
    }

    case 'warn': {
      stats.warned++
      // Forward original but with warning headers
      if (SHIELDX_MODE === 'warn') {
        // In warn mode, never block — just tag
        proxyToOllama(req, res, body, shieldxHeaders)
        return
      }
      proxyToOllama(req, res, body, shieldxHeaders)
      return
    }

    default: {
      stats.clean++
      proxyToOllama(req, res, body, shieldxHeaders)
      return
    }
  }
}

// ---------------------------------------------------------------------------
// Status endpoint (GET /shieldx/status)
// ---------------------------------------------------------------------------
function handleStatus(req, res) {
  if (req.method === 'GET' && req.url === '/shieldx/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({
      proxy: '@shieldx/ollama-proxy',
      version: '0.1.0',
      mode: SHIELDX_MODE,
      ollamaEndpoint: OLLAMA_ENDPOINT,
      ruleCount: getRuleCount(),
      stats,
      uptime: process.uptime(),
    }, null, 2))
    return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Direct scan endpoint (POST /shieldx/scan)
// ---------------------------------------------------------------------------
function handleScan(req, res) {
  if (req.method === 'POST' && req.url === '/shieldx/scan') {
    let body = ''
    req.on('data', (chunk) => { body += chunk })
    req.on('end', () => {
      try {
        const { input } = JSON.parse(body)
        if (!input) {
          res.writeHead(400, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'Missing "input" field' }))
          return
        }
        const result = scan(input)
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(result, null, 2))
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'Invalid JSON body' }))
      }
    })
    return true
  }
  return false
}

// ---------------------------------------------------------------------------
// Server creation
// ---------------------------------------------------------------------------
const server = createServer((req, res) => {
  // Handle internal endpoints
  if (handleStatus(req, res)) return
  if (handleScan(req, res)) return
  // All other requests go through the proxy handler
  handleRequest(req, res).catch((err) => {
    console.error(`${C.red}[UNHANDLED ERROR]${C.reset} ${err.stack}`)
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' })
    }
    res.end(JSON.stringify({ error: 'shieldx_internal_error', message: err.message }))
  })
})

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------
server.listen(PORT, () => {
  console.log('')
  console.log(`${C.bold}${C.cyan}  ____  _     _      _     _ __  __ ${C.reset}`)
  console.log(`${C.bold}${C.cyan} / ___|| |__ (_) ___| | __| |\\ \\/ / ${C.reset}`)
  console.log(`${C.bold}${C.cyan} \\___ \\| '_ \\| |/ _ \\ |/ _\` | \\  /  ${C.reset}`)
  console.log(`${C.bold}${C.cyan}  ___) | | | | |  __/ | (_| | /  \\  ${C.reset}`)
  console.log(`${C.bold}${C.cyan} |____/|_| |_|_|\\___|_|\\__,_|/_/\\_\\ ${C.reset}`)
  console.log(`${C.bold} Ollama Protection Proxy v0.1.0${C.reset}`)
  console.log('')
  console.log(`  ${C.green}Proxy listening${C.reset}    ${C.bold}http://localhost:${PORT}${C.reset}`)
  console.log(`  ${C.blue}Ollama upstream${C.reset}    ${C.bold}${OLLAMA_ENDPOINT}${C.reset}`)
  console.log(`  ${C.magenta}Protection mode${C.reset}    ${C.bold}${SHIELDX_MODE}${C.reset}`)
  console.log(`  ${C.yellow}Rules loaded${C.reset}        ${C.bold}${getRuleCount()}${C.reset}`)
  console.log(`  ${C.cyan}Status endpoint${C.reset}    ${C.bold}http://localhost:${PORT}/shieldx/status${C.reset}`)
  console.log('')
  console.log(`  ${C.dim}Configure clients:  export OLLAMA_HOST=http://localhost:${PORT}${C.reset}`)
  console.log(`  ${C.dim}Or point any Ollama client to port ${PORT} instead of 11434${C.reset}`)
  console.log('')
  console.log(`${C.dim}${'─'.repeat(64)}${C.reset}`)
  console.log('')
})

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`${C.red}[FATAL]${C.reset} Port ${PORT} is already in use.`)
    console.error(`  Try: PORT=${PORT + 1} node server.js`)
    process.exit(1)
  }
  console.error(`${C.red}[FATAL]${C.reset} ${err.message}`)
  process.exit(1)
})
