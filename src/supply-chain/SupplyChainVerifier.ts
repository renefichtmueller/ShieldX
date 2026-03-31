/**
 * Supply chain verification for ML models.
 * Verifies model file integrity via SHA-256 hashing and
 * scans for known pickle exploit patterns.
 */

import { createHash } from 'node:crypto'
import { readFile, stat } from 'node:fs/promises'

/** Maximum file size to scan for pickle exploits (100MB) */
const MAX_SCAN_SIZE = 100 * 1024 * 1024

/**
 * Known pickle exploit signatures and patterns.
 * These byte sequences indicate potentially malicious Python pickle payloads
 * that could execute arbitrary code when deserialized.
 */
const PICKLE_EXPLOIT_PATTERNS: readonly { readonly pattern: Buffer; readonly label: string }[] = [
  { pattern: Buffer.from('cos\nsystem\n', 'utf-8'), label: 'pickle-os-system' },
  { pattern: Buffer.from('csubprocess\n', 'utf-8'), label: 'pickle-subprocess' },
  { pattern: Buffer.from('c__builtin__\n', 'utf-8'), label: 'pickle-builtin' },
  { pattern: Buffer.from('cposix\nsystem\n', 'utf-8'), label: 'pickle-posix-system' },
  { pattern: Buffer.from('cos\npopen\n', 'utf-8'), label: 'pickle-os-popen' },
  { pattern: Buffer.from('cbuiltins\neval\n', 'utf-8'), label: 'pickle-eval' },
  { pattern: Buffer.from('cbuiltins\nexec\n', 'utf-8'), label: 'pickle-exec' },
  { pattern: Buffer.from('__reduce__', 'utf-8'), label: 'pickle-reduce-override' },
  { pattern: Buffer.from('cwebbrowser\nopen\n', 'utf-8'), label: 'pickle-webbrowser' },
  { pattern: Buffer.from('csocket\nsocket\n', 'utf-8'), label: 'pickle-socket' },
] as const

/** Pickle scan result */
interface PickleScanResult {
  readonly safe: boolean
  readonly indicators: readonly string[]
}

/**
 * SupplyChainVerifier — model file integrity verification.
 *
 * Provides two key capabilities:
 * 1. SHA-256 hash verification for model file integrity
 * 2. Pickle exploit scanning for serialized model files
 */
export class SupplyChainVerifier {
  /**
   * Verify a model file's SHA-256 hash matches expected value.
   * @param modelPath - Path to the model file
   * @param expectedHash - Expected SHA-256 hex digest
   * @returns True if hash matches
   */
  async verifyModelHash(modelPath: string, expectedHash: string): Promise<boolean> {
    const fileBuffer = await readFile(modelPath)
    const actualHash = createHash('sha256').update(fileBuffer).digest('hex')
    return actualHash === expectedHash.toLowerCase()
  }

  /**
   * Scan a file for known pickle exploit patterns.
   * @param filePath - Path to the file to scan
   * @returns Scan result with safety status and indicators
   */
  async scanForPickleExploits(filePath: string): Promise<PickleScanResult> {
    // Check file size
    const fileStats = await stat(filePath)
    if (fileStats.size > MAX_SCAN_SIZE) {
      return Object.freeze({
        safe: false,
        indicators: Object.freeze([`file-too-large:${fileStats.size}`]),
      })
    }

    const fileBuffer = await readFile(filePath)
    const indicators: string[] = []

    for (const entry of PICKLE_EXPLOIT_PATTERNS) {
      if (bufferContains(fileBuffer, entry.pattern)) {
        indicators.push(entry.label)
      }
    }

    // Also check for pickle protocol markers
    if (fileBuffer.length >= 2) {
      const firstByte = fileBuffer[0]
      // Pickle opcodes: \x80 = PROTO, \x89 = LONG_BINGET
      if (firstByte === 0x80) {
        // This is a pickle file — check version
        const version = fileBuffer[1]
        if (version !== undefined && version > 4) {
          indicators.push(`pickle-protocol-v${version}`)
        }
      }
    }

    return Object.freeze({
      safe: indicators.length === 0,
      indicators: Object.freeze([...indicators]),
    })
  }

  /**
   * Compute SHA-256 hash of a file.
   * @param filePath - Path to the file
   * @returns Hex-encoded SHA-256 hash
   */
  async computeHash(filePath: string): Promise<string> {
    const fileBuffer = await readFile(filePath)
    return createHash('sha256').update(fileBuffer).digest('hex')
  }
}

/** Check if a buffer contains a sub-buffer */
function bufferContains(haystack: Buffer, needle: Buffer): boolean {
  return haystack.includes(needle)
}
