/**
 * Manifest Verifier — RSA-signed tool manifest verification.
 * Ensures tool definitions have not been tampered with by comparing
 * cryptographic signatures of tool manifests.
 * Part of ShieldX Layer 7 (MCP Guard & Tool Security).
 */

import { createSign, createVerify, createHash } from 'node:crypto'

/** Tool entry in a manifest */
interface ManifestToolEntry {
  readonly name: string
  readonly description: string
  readonly version: string
}

/** Diff entry when comparing manifests */
interface ManifestDiff {
  readonly type: 'added' | 'removed' | 'modified'
  readonly toolName: string
  readonly details: string
}

/** Result of manifest comparison */
interface CompareResult {
  readonly match: boolean
  readonly diffs: readonly string[]
}

/**
 * Generates a deterministic JSON manifest from tool definitions.
 * Keys are sorted to ensure consistent serialization regardless of input order.
 *
 * @param tools - Array of tool definitions
 * @returns Deterministic JSON string representation
 */
export function generateManifest(
  tools: readonly ManifestToolEntry[],
): string {
  // Sort tools by name for deterministic output
  const sorted = [...tools].sort((a, b) => a.name.localeCompare(b.name))

  const manifest = {
    version: '1.0.0',
    generatedAt: new Date().toISOString(),
    checksum: '',
    tools: sorted.map(tool => ({
      name: tool.name,
      description: tool.description,
      version: tool.version,
    })),
  }

  // Calculate content checksum (excluding the checksum field itself)
  const contentForChecksum = JSON.stringify({
    tools: manifest.tools,
    version: manifest.version,
  })
  const checksum = createHash('sha256').update(contentForChecksum).digest('hex')

  return JSON.stringify(
    { ...manifest, checksum },
    null,
    2,
  )
}

/**
 * Signs a manifest string with an RSA private key using RSA-SHA256.
 *
 * @param manifest - The JSON manifest string to sign
 * @param privateKey - PEM-encoded RSA private key
 * @returns Base64-encoded RSA-SHA256 signature
 */
export function signManifest(manifest: string, privateKey: string): string {
  const signer = createSign('RSA-SHA256')
  signer.update(manifest)
  signer.end()
  return signer.sign(privateKey, 'base64')
}

/**
 * Verifies a manifest signature against an RSA public key.
 *
 * @param manifest - The JSON manifest string
 * @param signature - Base64-encoded RSA-SHA256 signature
 * @param publicKey - PEM-encoded RSA public key
 * @returns True if the signature is valid
 */
export function verifyManifest(
  manifest: string,
  signature: string,
  publicKey: string,
): boolean {
  try {
    const verifier = createVerify('RSA-SHA256')
    verifier.update(manifest)
    verifier.end()
    return verifier.verify(publicKey, signature, 'base64')
  } catch {
    return false
  }
}

/**
 * Parses a manifest JSON string into its tool entries.
 */
function parseManifestTools(
  manifestJson: string,
): readonly ManifestToolEntry[] {
  try {
    const parsed = JSON.parse(manifestJson) as {
      readonly tools?: readonly ManifestToolEntry[]
    }
    return parsed.tools ?? []
  } catch {
    return []
  }
}

/**
 * Compares a stored manifest with a current manifest to detect changes.
 * Reports added, removed, and modified tools.
 *
 * @param stored - Previously stored manifest JSON
 * @param current - Current manifest JSON to compare
 * @returns Whether manifests match, with detailed diffs
 */
export function compareManifest(
  stored: string,
  current: string,
): CompareResult {
  const storedTools = parseManifestTools(stored)
  const currentTools = parseManifestTools(current)

  const storedMap = new Map<string, ManifestToolEntry>()
  for (const tool of storedTools) {
    storedMap.set(tool.name, tool)
  }

  const currentMap = new Map<string, ManifestToolEntry>()
  for (const tool of currentTools) {
    currentMap.set(tool.name, tool)
  }

  const diffs: ManifestDiff[] = []

  // Check for removed and modified tools
  for (const [name, storedTool] of storedMap) {
    const currentTool = currentMap.get(name)
    if (currentTool === undefined) {
      diffs.push({
        type: 'removed',
        toolName: name,
        details: `Tool "${name}" was removed`,
      })
    } else {
      const changes: string[] = []
      if (storedTool.description !== currentTool.description) {
        changes.push('description changed')
      }
      if (storedTool.version !== currentTool.version) {
        changes.push(`version: ${storedTool.version} -> ${currentTool.version}`)
      }
      if (changes.length > 0) {
        diffs.push({
          type: 'modified',
          toolName: name,
          details: `Tool "${name}" modified: ${changes.join(', ')}`,
        })
      }
    }
  }

  // Check for added tools
  for (const name of currentMap.keys()) {
    if (!storedMap.has(name)) {
      diffs.push({
        type: 'added',
        toolName: name,
        details: `Tool "${name}" was added`,
      })
    }
  }

  return {
    match: diffs.length === 0,
    diffs: diffs.map(d => d.details),
  }
}

/**
 * Computes the SHA-256 hash of a manifest for storage.
 *
 * @param manifest - The manifest JSON string
 * @returns Hex-encoded SHA-256 hash
 */
export function hashManifest(manifest: string): string {
  return createHash('sha256').update(manifest).digest('hex')
}
