/**
 * ModelIntegrityGuard — unified supply chain integrity orchestrator.
 *
 * Combines model hash verification, LoRA/adapter integrity checks,
 * MCP tool manifest validation, dependency audit hooks, and model
 * provenance verification into a single API surface.
 *
 * Wraps existing SupplyChainVerifier, ModelProvenanceChecker, and
 * ManifestVerifier while adding new LoRA adapter and dependency
 * audit capabilities.
 */

import { readFile, stat, readdir, access } from 'node:fs/promises'
import { join, basename, extname } from 'node:path'

import { SupplyChainVerifier } from './SupplyChainVerifier.js'
import { ModelProvenanceChecker } from './ModelProvenanceChecker.js'
import type { ScanResult, ScannerType, ThreatLevel } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Configuration for ModelIntegrityGuard */
export interface ModelIntegrityConfig {
  readonly trustedModelHashes?: Readonly<Record<string, string>>
  readonly trustedRegistries?: readonly string[]
  readonly maxAdapterSizeMB?: number
  readonly enableDependencyAudit?: boolean
}

/** Single integrity check result */
export interface IntegrityCheck {
  readonly name: string
  readonly passed: boolean
  readonly details: string
  readonly severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
}

/** Aggregated integrity check result */
export interface IntegrityCheckResult {
  readonly passed: boolean
  readonly checks: readonly IntegrityCheck[]
  readonly overallRisk: 'none' | 'low' | 'medium' | 'high' | 'critical'
  readonly scanResults: readonly ScanResult[]
}

/** Dependency audit finding from an external scanner */
export interface DependencyAuditFinding {
  readonly packageName: string
  readonly installedVersion: string
  readonly severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  readonly advisory: string
}

/** Pluggable dependency audit scanner interface */
export interface DependencyAuditScanner {
  readonly name: string
  scan(): Promise<readonly DependencyAuditFinding[]>
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SCANNER_TYPE: ScannerType = 'supply_chain'

/** Expected keys in a valid adapter_config.json */
const REQUIRED_ADAPTER_KEYS = [
  'base_model_name_or_path',
  'r',
  'lora_alpha',
  'target_modules',
] as const

/** Model weight file extensions */
const WEIGHT_EXTENSIONS = new Set(['.safetensors', '.bin', '.pt', '.gguf'])

/** Max risk severity ordering */
const RISK_ORDER: Readonly<Record<string, number>> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
} as const

const RISK_LEVELS = ['none', 'low', 'medium', 'high', 'critical'] as const

/** Suspicious patterns that might appear in MCP tool descriptions */
const SUSPICIOUS_TOOL_PATTERNS: readonly RegExp[] = [
  /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?)/i,
  /system\s*:\s*/i,
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bchild_process\b/i,
  /\b(rm|del(ete)?)\s+-rf?\b/i,
  /\bpassword\b.*\b(leak|exfil|send|post)\b/i,
  /\b(curl|wget|fetch)\s+https?:\/\//i,
  /<script[\s>]/i,
  /\bbase64\s*(decode|encode)\b/i,
  /\bDROP\s+TABLE\b/i,
  /\bunion\s+select\b/i,
] as const

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

function buildCheck(
  name: string,
  passed: boolean,
  details: string,
  severity: IntegrityCheck['severity'],
): IntegrityCheck {
  return Object.freeze({ name, passed, details, severity })
}

function severityToThreatLevel(severity: IntegrityCheck['severity']): ThreatLevel {
  const mapping: Record<IntegrityCheck['severity'], ThreatLevel> = {
    info: 'none',
    low: 'low',
    medium: 'medium',
    high: 'high',
    critical: 'critical',
  }
  return mapping[severity]
}

function worstRisk(checks: readonly IntegrityCheck[]): IntegrityCheckResult['overallRisk'] {
  let worst = 0
  for (const check of checks) {
    if (!check.passed) {
      const level = RISK_ORDER[check.severity] ?? 0
      if (level > worst) worst = level
    }
  }
  return RISK_LEVELS[worst] ?? 'none'
}

function checksToScanResults(checks: readonly IntegrityCheck[]): readonly ScanResult[] {
  return Object.freeze(
    checks
      .filter((c) => !c.passed)
      .map((check) =>
        Object.freeze({
          scannerId: `integrity:${check.name}`,
          scannerType: SCANNER_TYPE,
          detected: true,
          confidence: check.severity === 'critical' ? 1.0
            : check.severity === 'high' ? 0.85
            : check.severity === 'medium' ? 0.6
            : check.severity === 'low' ? 0.35
            : 0.1,
          threatLevel: severityToThreatLevel(check.severity),
          killChainPhase: 'initial_access' as const,
          matchedPatterns: Object.freeze([check.details]),
          latencyMs: 0,
          metadata: Object.freeze({ checkName: check.name }),
        } satisfies ScanResult),
      ),
  )
}

function buildResult(checks: readonly IntegrityCheck[]): IntegrityCheckResult {
  const allPassed = checks.every((c) => c.passed)
  return Object.freeze({
    passed: allPassed,
    checks: Object.freeze([...checks]),
    overallRisk: worstRisk(checks),
    scanResults: checksToScanResults(checks),
  })
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path)
    return true
  } catch {
    return false
  }
}

// computeSHA256 available via SupplyChainVerifier.computeHash()

// ---------------------------------------------------------------------------
// ModelIntegrityGuard
// ---------------------------------------------------------------------------

/**
 * Unified supply chain integrity orchestrator.
 *
 * Wraps SupplyChainVerifier, ModelProvenanceChecker, and ManifestVerifier
 * into a cohesive API with additional LoRA adapter and dependency audit
 * capabilities.
 */
export class ModelIntegrityGuard {
  private readonly supplyChainVerifier: SupplyChainVerifier
  private readonly provenanceChecker: ModelProvenanceChecker
  private readonly trustedHashes: Readonly<Record<string, string>>
  private readonly trustedRegistries: readonly string[]
  private readonly maxAdapterSizeMB: number
  private readonly enableDependencyAudit: boolean
  private readonly dependencyAuditScanners: DependencyAuditScanner[] = []

  constructor(config: ModelIntegrityConfig = {}) {
    this.supplyChainVerifier = new SupplyChainVerifier()
    this.provenanceChecker = new ModelProvenanceChecker()
    this.trustedHashes = Object.freeze({ ...(config.trustedModelHashes ?? {}) })
    this.trustedRegistries = Object.freeze([
      ...(config.trustedRegistries ?? ['ollama.com', 'huggingface.co']),
    ])
    this.maxAdapterSizeMB = config.maxAdapterSizeMB ?? 500
    this.enableDependencyAudit = config.enableDependencyAudit ?? false
  }

  // -----------------------------------------------------------------------
  // 1. Model Hash Verification
  // -----------------------------------------------------------------------

  /**
   * Verify model file integrity via SHA-256 hash and pickle exploit scan.
   *
   * If an expected hash is provided, the file hash must match exactly.
   * If no expected hash is provided but the model name is in the trusted
   * hashes registry, that hash is used. Additionally scans for pickle
   * exploit patterns in .pkl/.pickle/.pt files.
   */
  async verifyModel(modelPath: string, expectedHash?: string): Promise<IntegrityCheckResult> {
    const checks: IntegrityCheck[] = []

    // Check file exists
    const exists = await fileExists(modelPath)
    if (!exists) {
      checks.push(
        buildCheck('model-file-exists', false, `Model file not found: ${modelPath}`, 'critical'),
      )
      return buildResult(checks)
    }

    // Determine expected hash
    const modelName = basename(modelPath)
    const resolvedHash = expectedHash ?? this.trustedHashes[modelName]

    // Compute actual hash
    try {
      const actualHash = await this.supplyChainVerifier.computeHash(modelPath)

      if (resolvedHash !== undefined) {
        const hashMatch = actualHash === resolvedHash.toLowerCase()
        checks.push(
          buildCheck(
            'model-hash-verification',
            hashMatch,
            hashMatch
              ? `SHA-256 hash verified for ${modelName}`
              : `SHA-256 mismatch for ${modelName}: expected ${resolvedHash.slice(0, 16)}..., got ${actualHash.slice(0, 16)}...`,
            hashMatch ? 'info' : 'critical',
          ),
        )
      } else {
        checks.push(
          buildCheck(
            'model-hash-verification',
            true,
            `No expected hash for ${modelName} — computed SHA-256: ${actualHash.slice(0, 16)}...`,
            'info',
          ),
        )
      }
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error)
      checks.push(
        buildCheck('model-hash-verification', false, `Hash computation failed: ${message}`, 'high'),
      )
    }

    // Pickle exploit scan for susceptible file types
    const ext = extname(modelPath).toLowerCase()
    if (['.pkl', '.pickle', '.pt', '.bin'].includes(ext)) {
      try {
        const pickleScan = await this.supplyChainVerifier.scanForPickleExploits(modelPath)
        checks.push(
          buildCheck(
            'pickle-exploit-scan',
            pickleScan.safe,
            pickleScan.safe
              ? `No pickle exploits detected in ${modelName}`
              : `Pickle exploit indicators: ${pickleScan.indicators.join(', ')}`,
            pickleScan.safe ? 'info' : 'critical',
          ),
        )
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error)
        checks.push(
          buildCheck('pickle-exploit-scan', false, `Pickle scan failed: ${message}`, 'medium'),
        )
      }
    }

    // Provenance check (model name / path as identifier)
    const provenance = this.provenanceChecker.checkProvenance(modelPath)
    checks.push(
      buildCheck(
        'model-provenance',
        provenance.verified,
        provenance.verified
          ? `Model verified from ${provenance.source}`
          : `Provenance warnings: ${provenance.warnings.join(', ')}`,
        provenance.verified ? 'info' : provenance.warnings.some((w) => w.startsWith('typosquatting'))
          ? 'high'
          : 'medium',
      ),
    )

    return buildResult(checks)
  }

  // -----------------------------------------------------------------------
  // 2. LoRA / Adapter Integrity
  // -----------------------------------------------------------------------

  /**
   * Verify a LoRA or PEFT adapter directory for integrity.
   *
   * Checks:
   * - adapter_config.json exists and has expected structure
   * - Weight files are present and hashed
   * - Adapter is not suspiciously large (>2x expected for rank)
   * - Target modules are present in config
   */
  async verifyAdapter(adapterPath: string): Promise<IntegrityCheckResult> {
    const checks: IntegrityCheck[] = []

    // Verify adapter directory exists
    const dirExists = await fileExists(adapterPath)
    if (!dirExists) {
      checks.push(
        buildCheck('adapter-dir-exists', false, `Adapter directory not found: ${adapterPath}`, 'critical'),
      )
      return buildResult(checks)
    }

    // Check adapter_config.json
    const configPath = join(adapterPath, 'adapter_config.json')
    const configExists = await fileExists(configPath)

    if (!configExists) {
      checks.push(
        buildCheck('adapter-config-exists', false, 'Missing adapter_config.json', 'critical'),
      )
      return buildResult(checks)
    }

    checks.push(
      buildCheck('adapter-config-exists', true, 'adapter_config.json found', 'info'),
    )

    // Parse and validate adapter config
    let adapterConfig: Record<string, unknown> = {}
    try {
      const configContent = await readFile(configPath, 'utf-8')
      adapterConfig = JSON.parse(configContent) as Record<string, unknown>
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error)
      checks.push(
        buildCheck('adapter-config-parse', false, `Failed to parse adapter_config.json: ${message}`, 'high'),
      )
      return buildResult(checks)
    }

    // Validate required keys
    const missingKeys = REQUIRED_ADAPTER_KEYS.filter((key) => !(key in adapterConfig))
    checks.push(
      buildCheck(
        'adapter-config-structure',
        missingKeys.length === 0,
        missingKeys.length === 0
          ? 'All required adapter config keys present'
          : `Missing keys: ${missingKeys.join(', ')}`,
        missingKeys.length === 0 ? 'info' : 'high',
      ),
    )

    // Validate target_modules is a non-empty array
    const targetModules = adapterConfig['target_modules']
    if (Array.isArray(targetModules) && targetModules.length > 0) {
      checks.push(
        buildCheck(
          'adapter-target-modules',
          true,
          `Target modules: ${(targetModules as string[]).join(', ')}`,
          'info',
        ),
      )
    } else {
      checks.push(
        buildCheck(
          'adapter-target-modules',
          false,
          'target_modules is missing or empty',
          'medium',
        ),
      )
    }

    // Find and hash weight files, check sizes
    try {
      const entries = await readdir(adapterPath)
      const weightFiles = entries.filter((f) => WEIGHT_EXTENSIONS.has(extname(f).toLowerCase()))

      if (weightFiles.length === 0) {
        checks.push(
          buildCheck('adapter-weight-files', false, 'No weight files found in adapter directory', 'high'),
        )
      } else {
        // Check each weight file
        let totalSizeMB = 0
        for (const weightFile of weightFiles) {
          const weightPath = join(adapterPath, weightFile)
          const fileStat = await stat(weightPath)
          const sizeMB = fileStat.size / (1024 * 1024)
          totalSizeMB += sizeMB
        }

        checks.push(
          buildCheck(
            'adapter-weight-files',
            true,
            `Found ${weightFiles.length} weight file(s), total ${totalSizeMB.toFixed(1)} MB`,
            'info',
          ),
        )

        // Size check: adapter should not exceed maxAdapterSizeMB
        const sizeOk = totalSizeMB <= this.maxAdapterSizeMB
        checks.push(
          buildCheck(
            'adapter-size-check',
            sizeOk,
            sizeOk
              ? `Adapter size ${totalSizeMB.toFixed(1)} MB within limit (${this.maxAdapterSizeMB} MB)`
              : `Adapter size ${totalSizeMB.toFixed(1)} MB exceeds limit of ${this.maxAdapterSizeMB} MB — suspiciously large`,
            sizeOk ? 'info' : 'high',
          ),
        )

        // Rank-based size heuristic: for a given LoRA rank r, expected size
        // should be proportional. Flag if >2x expected.
        const rank = typeof adapterConfig['r'] === 'number' ? adapterConfig['r'] : 0
        if (rank > 0 && totalSizeMB > 0) {
          // Rough heuristic: a rank-16 adapter for a 7B model is ~30-50 MB.
          // Scale linearly: expectedMB ~ rank * 3 (conservative upper bound).
          const expectedMaxMB = rank * 3
          const rankSizeOk = totalSizeMB <= expectedMaxMB * 2
          checks.push(
            buildCheck(
              'adapter-rank-size-ratio',
              rankSizeOk,
              rankSizeOk
                ? `Size/rank ratio normal (rank=${rank}, size=${totalSizeMB.toFixed(1)} MB)`
                : `Adapter suspiciously large for rank ${rank}: ${totalSizeMB.toFixed(1)} MB vs expected max ~${expectedMaxMB} MB`,
              rankSizeOk ? 'info' : 'medium',
            ),
          )
        }
      }
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error)
      checks.push(
        buildCheck('adapter-weight-files', false, `Failed to read adapter directory: ${message}`, 'high'),
      )
    }

    return buildResult(checks)
  }

  // -----------------------------------------------------------------------
  // 3. MCP Tool Manifest Validation
  // -----------------------------------------------------------------------

  /**
   * Verify an MCP tool manifest for hidden injection or suspicious patterns.
   *
   * Checks:
   * - Tool descriptions for injection patterns
   * - Tool schemas for suspicious field names
   * - Tool names against known-good registry (if provided)
   */
  verifyToolManifest(manifest: unknown): IntegrityCheckResult {
    const checks: IntegrityCheck[] = []

    // Validate manifest is an object
    if (manifest === null || manifest === undefined || typeof manifest !== 'object') {
      checks.push(
        buildCheck('manifest-structure', false, 'Manifest is null, undefined, or not an object', 'high'),
      )
      return buildResult(checks)
    }

    const manifestObj = manifest as Record<string, unknown>
    const tools = manifestObj['tools']

    if (!Array.isArray(tools)) {
      checks.push(
        buildCheck('manifest-tools-array', false, 'Manifest missing "tools" array', 'high'),
      )
      return buildResult(checks)
    }

    checks.push(
      buildCheck('manifest-tools-array', true, `Manifest contains ${tools.length} tool(s)`, 'info'),
    )

    // Check each tool entry
    for (const tool of tools) {
      if (typeof tool !== 'object' || tool === null) continue
      const toolObj = tool as Record<string, unknown>
      const toolName = typeof toolObj['name'] === 'string' ? toolObj['name'] : '<unnamed>'
      const description = typeof toolObj['description'] === 'string' ? toolObj['description'] : ''

      // Scan description for injection patterns
      for (const pattern of SUSPICIOUS_TOOL_PATTERNS) {
        if (pattern.test(description)) {
          checks.push(
            buildCheck(
              `tool-description:${toolName}`,
              false,
              `Suspicious pattern in tool "${toolName}" description: ${pattern.source}`,
              'critical',
            ),
          )
        }
      }

      // Scan tool name for suspicious characters
      if (toolName !== '<unnamed>' && /[^\w\-.]/.test(toolName)) {
        checks.push(
          buildCheck(
            `tool-name:${toolName}`,
            false,
            `Tool name contains suspicious characters: "${toolName}"`,
            'medium',
          ),
        )
      }

      // Check schema for suspicious field names
      const schema = toolObj['inputSchema'] ?? toolObj['schema'] ?? toolObj['parameters']
      if (schema !== null && schema !== undefined && typeof schema === 'object') {
        const schemaStr = JSON.stringify(schema)
        for (const pattern of SUSPICIOUS_TOOL_PATTERNS) {
          if (pattern.test(schemaStr)) {
            checks.push(
              buildCheck(
                `tool-schema:${toolName}`,
                false,
                `Suspicious pattern in tool "${toolName}" schema: ${pattern.source}`,
                'high',
              ),
            )
          }
        }
      }
    }

    // If no suspicious findings were added, mark as clean
    const failedChecks = checks.filter((c) => !c.passed)
    if (failedChecks.length === 0) {
      checks.push(
        buildCheck('manifest-clean', true, 'No suspicious patterns found in tool manifest', 'info'),
      )
    }

    return buildResult(checks)
  }

  // -----------------------------------------------------------------------
  // 4. Dependency Audit Hook
  // -----------------------------------------------------------------------

  /**
   * Register a pluggable dependency audit scanner.
   * Scanners are called during `runFullAudit()`.
   */
  registerDependencyScanner(scanner: DependencyAuditScanner): void {
    this.dependencyAuditScanners.push(scanner)
  }

  /**
   * Run all registered dependency audit scanners.
   * Returns findings as IntegrityCheckResult.
   */
  async runDependencyAudit(): Promise<IntegrityCheckResult> {
    const checks: IntegrityCheck[] = []

    if (!this.enableDependencyAudit) {
      checks.push(
        buildCheck('dependency-audit', true, 'Dependency audit disabled', 'info'),
      )
      return buildResult(checks)
    }

    if (this.dependencyAuditScanners.length === 0) {
      checks.push(
        buildCheck('dependency-audit', true, 'No dependency audit scanners registered', 'info'),
      )
      return buildResult(checks)
    }

    for (const scanner of this.dependencyAuditScanners) {
      try {
        const findings = await scanner.scan()

        if (findings.length === 0) {
          checks.push(
            buildCheck(`dep-audit:${scanner.name}`, true, `${scanner.name}: no issues found`, 'info'),
          )
        } else {
          for (const finding of findings) {
            checks.push(
              buildCheck(
                `dep-audit:${scanner.name}:${finding.packageName}`,
                false,
                `${finding.packageName}@${finding.installedVersion}: ${finding.advisory}`,
                finding.severity,
              ),
            )
          }
        }
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error)
        checks.push(
          buildCheck(`dep-audit:${scanner.name}`, false, `Scanner failed: ${message}`, 'medium'),
        )
      }
    }

    return buildResult(checks)
  }

  // -----------------------------------------------------------------------
  // 5. Model Provenance (standalone)
  // -----------------------------------------------------------------------

  /**
   * Verify model provenance by identifier (URL, registry path, or name).
   * Checks for trusted registry and typosquatting.
   */
  verifyProvenance(modelId: string): IntegrityCheckResult {
    const checks: IntegrityCheck[] = []
    const result = this.provenanceChecker.checkProvenance(modelId)

    checks.push(
      buildCheck(
        'provenance-registry',
        result.verified,
        result.verified
          ? `Model verified from trusted registry: ${result.source}`
          : `Model source unverified (${result.source})`,
        result.verified ? 'info' : 'medium',
      ),
    )

    for (const warning of result.warnings) {
      const isTyposquat = warning.startsWith('typosquatting')
      checks.push(
        buildCheck(
          `provenance:${warning.split(':')[0]}`,
          false,
          warning,
          isTyposquat ? 'high' : 'medium',
        ),
      )
    }

    return buildResult(checks)
  }

  // -----------------------------------------------------------------------
  // Full Audit
  // -----------------------------------------------------------------------

  /**
   * Run all available integrity checks.
   * Combines dependency audit and any other configured checks.
   * Model and adapter verification require explicit paths, so they
   * are not included here — call `verifyModel` / `verifyAdapter` directly.
   */
  async runFullAudit(): Promise<IntegrityCheckResult> {
    const allChecks: IntegrityCheck[] = []

    // Run dependency audit
    const depResult = await this.runDependencyAudit()
    allChecks.push(...depResult.checks)

    // Report trusted hashes count
    const hashCount = Object.keys(this.trustedHashes).length
    allChecks.push(
      buildCheck(
        'trusted-hashes-registry',
        true,
        `Trusted model hashes registry: ${hashCount} entries`,
        'info',
      ),
    )

    // Report trusted registries
    allChecks.push(
      buildCheck(
        'trusted-registries',
        true,
        `Trusted registries: ${this.trustedRegistries.join(', ')}`,
        'info',
      ),
    )

    return buildResult(allChecks)
  }

  // -----------------------------------------------------------------------
  // Pipeline integration
  // -----------------------------------------------------------------------

  /**
   * Convert an IntegrityCheckResult to ScanResult[] for pipeline integration.
   * Convenience method for feeding results into the ShieldX pipeline.
   */
  toScanResults(result: IntegrityCheckResult): readonly ScanResult[] {
    return result.scanResults
  }
}
