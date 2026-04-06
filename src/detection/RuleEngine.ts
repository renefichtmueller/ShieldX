/**
 * High-performance regex-based rule engine (Layer 1).
 * This is the FASTEST detection layer, targeting <2ms scan time.
 * Pre-compiles all regexes at construction for zero allocation during scans.
 */

import type { ScanResult, ShieldXConfig, ThreatLevel } from '../types/detection'
import type { InjectionRule } from './rules/base.rules'

import { rules as baseRules } from './rules/base.rules'
import { rules as jailbreakRules } from './rules/jailbreak.rules'
import { rules as extractionRules } from './rules/extraction.rules'
import { rules as delimiterRules } from './rules/delimiter.rules'
import { rules as encodingRules } from './rules/encoding.rules'
import { rules as persistenceRules } from './rules/persistence.rules'
import { rules as exfiltrationRules } from './rules/exfiltration.rules'
import { rules as mcpRules } from './rules/mcp.rules'
import { rules as multilingualRules } from './rules/multilingual.rules'
import { rules as dnsCovertChannelRules } from './rules/dns-covert-channel.rules'
import { rules as authorityClaimRules } from './rules/authority-claim.rules'

/**
 * Map a confidence score to a threat level.
 * Thresholds are derived from ShieldXConfig but defaults are provided.
 */
function confidenceToThreatLevel(
  confidence: number,
  thresholds: ShieldXConfig['thresholds']
): ThreatLevel {
  if (confidence >= thresholds.critical) return 'critical'
  if (confidence >= thresholds.high) return 'high'
  if (confidence >= thresholds.medium) return 'medium'
  if (confidence >= thresholds.low) return 'low'
  return 'none'
}

/**
 * RuleEngine — Layer 1 of the ShieldX defense pipeline.
 *
 * Performs high-speed regex matching against a library of injection patterns.
 * All regexes are pre-compiled at construction time. The scan method iterates
 * through enabled rules and returns ScanResult objects for every match.
 *
 * Target performance: <2ms for full rule set against typical input.
 */
export class RuleEngine {
  private readonly rules: InjectionRule[] = []
  private readonly thresholds: ShieldXConfig['thresholds']

  /**
   * Construct a RuleEngine, loading all built-in rules.
   * @param config - ShieldX configuration for threshold values
   */
  constructor(config: ShieldXConfig) {
    this.thresholds = config.thresholds
    this.loadBuiltinRules()
  }

  /**
   * Scan input text against all enabled rules.
   * Returns a ScanResult for every rule that matches.
   * @param input - The text to scan for injection patterns
   * @returns Array of ScanResult objects for detected patterns
   */
  scan(input: string): readonly ScanResult[] {
    const start = performance.now()
    const results: ScanResult[] = []

    for (const rule of this.rules) {
      if (!rule.enabled) continue

      const match = rule.pattern.test(input)
      if (match) {
        const latencyMs = performance.now() - start

        results.push({
          scannerId: rule.id,
          scannerType: 'rule',
          detected: true,
          confidence: rule.confidence,
          threatLevel: confidenceToThreatLevel(rule.confidence, this.thresholds),
          killChainPhase: rule.phase,
          matchedPatterns: [rule.description],
          latencyMs,
          metadata: {
            ruleId: rule.id,
            category: rule.category,
          },
        })
      }

      // Reset lastIndex for stateful regex patterns (those with /g flag)
      rule.pattern.lastIndex = 0
    }

    return results
  }

  /**
   * Add a single rule dynamically at runtime.
   * @param rule - The injection rule to add
   */
  addRule(rule: InjectionRule): void {
    this.rules.push(rule)
  }

  /**
   * Remove a rule by its ID.
   * @param ruleId - The unique identifier of the rule to remove
   */
  removeRule(ruleId: string): void {
    const index = this.rules.findIndex((r) => r.id === ruleId)
    if (index !== -1) {
      this.rules.splice(index, 1)
    }
  }

  /**
   * Bulk load rules, replacing any existing rules with matching IDs.
   * Rules with new IDs are appended.
   * @param rules - Array of injection rules to load
   */
  loadRules(rules: readonly InjectionRule[]): void {
    for (const rule of rules) {
      const existingIndex = this.rules.findIndex((r) => r.id === rule.id)
      if (existingIndex !== -1) {
        this.rules[existingIndex] = rule
      } else {
        this.rules.push(rule)
      }
    }
  }

  /**
   * Get the total number of loaded rules (enabled + disabled).
   * @returns The count of all loaded rules
   */
  getRuleCount(): number {
    return this.rules.length
  }

  /**
   * Get the number of currently enabled rules.
   * @returns The count of enabled rules
   */
  getEnabledRuleCount(): number {
    return this.rules.filter((r) => r.enabled).length
  }

  /** Load all built-in rule modules */
  private loadBuiltinRules(): void {
    const allRules: readonly (readonly InjectionRule[])[] = [
      baseRules,
      jailbreakRules,
      extractionRules,
      delimiterRules,
      encodingRules,
      persistenceRules,
      exfiltrationRules,
      mcpRules,
      multilingualRules,
      dnsCovertChannelRules,
      authorityClaimRules,
    ]

    for (const ruleSet of allRules) {
      for (const rule of ruleSet) {
        this.rules.push(rule)
      }
    }
  }
}
