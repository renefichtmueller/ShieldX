/**
 * CredentialRedactor — API key, secret, and credential redaction.
 *
 * Detects and redacts sensitive credentials from input before processing.
 * Inspired by Microsoft Presidio patterns, covers API keys, AWS credentials,
 * JWT tokens, passwords in URLs, email addresses, credit card numbers,
 * SSH keys, and more.
 *
 * IMPORTANT: Never logs the actual secret values.
 */

import type { ShieldXConfig } from '../types/detection.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Result of credential redaction */
export interface RedactionResult {
  readonly redacted: string
  readonly foundSecrets: number
  readonly secretTypes: readonly string[]
}

/** Internal match descriptor */
interface SecretMatch {
  readonly type: string
  readonly redactionLabel: string
  readonly pattern: RegExp
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Credential patterns — ordered by specificity (most specific first).
 * Each entry includes a human-readable type and a redaction label.
 */
const SECRET_PATTERNS: readonly SecretMatch[] = Object.freeze([
  // OpenAI API keys
  {
    type: 'openai_api_key',
    redactionLabel: '[REDACTED_OPENAI_KEY]',
    pattern: /\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b/g,
  },
  // OpenAI project keys
  {
    type: 'openai_project_key',
    redactionLabel: '[REDACTED_OPENAI_KEY]',
    pattern: /\bsk-proj-[A-Za-z0-9_-]{40,}\b/g,
  },
  // Generic sk- prefixed keys
  {
    type: 'secret_key',
    redactionLabel: '[REDACTED_API_KEY]',
    pattern: /\bsk-[A-Za-z0-9]{32,}\b/g,
  },
  // Slack tokens
  {
    type: 'slack_token',
    redactionLabel: '[REDACTED_SLACK_TOKEN]',
    pattern: /\bxox[bporas]-[A-Za-z0-9-]{10,}\b/g,
  },
  // GitHub tokens
  {
    type: 'github_token',
    redactionLabel: '[REDACTED_GITHUB_TOKEN]',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g,
  },
  // GitHub fine-grained PAT
  {
    type: 'github_fine_grained_token',
    redactionLabel: '[REDACTED_GITHUB_TOKEN]',
    pattern: /\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b/g,
  },
  // AWS Access Key ID
  {
    type: 'aws_access_key',
    redactionLabel: '[REDACTED_AWS_KEY]',
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  },
  // AWS Secret Access Key
  {
    type: 'aws_secret_key',
    redactionLabel: '[REDACTED_AWS_SECRET]',
    pattern: /(?<=aws_secret_access_key\s*[=:]\s*)[A-Za-z0-9/+=]{40}\b/g,
  },
  // Google API keys
  {
    type: 'google_api_key',
    redactionLabel: '[REDACTED_GOOGLE_KEY]',
    pattern: /\bAIza[A-Za-z0-9_-]{35}\b/g,
  },
  // Stripe keys
  {
    type: 'stripe_key',
    redactionLabel: '[REDACTED_STRIPE_KEY]',
    pattern: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
  },
  // Twilio
  {
    type: 'twilio_key',
    redactionLabel: '[REDACTED_TWILIO_KEY]',
    pattern: /\bSK[a-f0-9]{32}\b/g,
  },
  // SendGrid
  {
    type: 'sendgrid_key',
    redactionLabel: '[REDACTED_SENDGRID_KEY]',
    pattern: /\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}\b/g,
  },
  // Mailgun
  {
    type: 'mailgun_key',
    redactionLabel: '[REDACTED_MAILGUN_KEY]',
    pattern: /\bkey-[a-f0-9]{32}\b/g,
  },
  // JWT tokens
  {
    type: 'jwt_token',
    redactionLabel: '[REDACTED_JWT]',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
  // Generic Bearer tokens
  {
    type: 'bearer_token',
    redactionLabel: '[REDACTED_BEARER_TOKEN]',
    pattern: /\bBearer\s+[A-Za-z0-9_.-]{20,}\b/gi,
  },
  // Heroku API key
  {
    type: 'heroku_key',
    redactionLabel: '[REDACTED_HEROKU_KEY]',
    pattern: /\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g,
  },
  // RSA Private Key headers
  {
    type: 'private_key',
    redactionLabel: '[REDACTED_PRIVATE_KEY]',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
  },
  // SSH keys (public)
  {
    type: 'ssh_key',
    redactionLabel: '[REDACTED_SSH_KEY]',
    pattern: /\bssh-(?:rsa|ed25519|ecdsa)\s+[A-Za-z0-9+/=]{40,}\b/g,
  },
  // Password in URL
  {
    type: 'password_in_url',
    redactionLabel: '[REDACTED_PASSWORD_URL]',
    pattern: /:\/\/[^:@\s]+:([^@\s]{3,})@/g,
  },
  // Generic password assignments
  {
    type: 'password_assignment',
    redactionLabel: '[REDACTED_PASSWORD]',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*["']?[^\s"']{4,}["']?/gi,
  },
  // Credit card numbers (Luhn-checkable patterns)
  {
    type: 'credit_card',
    redactionLabel: '[REDACTED_CREDIT_CARD]',
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
  },
  // Email addresses
  {
    type: 'email_address',
    redactionLabel: '[REDACTED_EMAIL]',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  },
  // Anthropic API keys
  {
    type: 'anthropic_key',
    redactionLabel: '[REDACTED_ANTHROPIC_KEY]',
    pattern: /\bsk-ant-[A-Za-z0-9_-]{40,}\b/g,
  },
  // Hugging Face tokens
  {
    type: 'huggingface_token',
    redactionLabel: '[REDACTED_HF_TOKEN]',
    pattern: /\bhf_[A-Za-z0-9]{34,}\b/g,
  },
  // Cloudflare API tokens
  {
    type: 'cloudflare_token',
    redactionLabel: '[REDACTED_CF_TOKEN]',
    pattern: /\b[A-Za-z0-9_-]{40}\b(?=.*cloudflare)/gi,
  },
  // Database connection strings
  {
    type: 'database_url',
    redactionLabel: '[REDACTED_DATABASE_URL]',
    pattern: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"']+/gi,
  },
  // Generic hex secrets (32+ chars in key context)
  {
    type: 'hex_secret',
    redactionLabel: '[REDACTED_SECRET]',
    pattern: /(?:secret|token|api[_-]?key)\s*[=:]\s*["']?[a-f0-9]{32,}["']?/gi,
  },
])

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * Credential Redactor.
 *
 * Scans input for API keys, secrets, passwords, tokens, and other
 * sensitive credentials. Replaces matches with labeled redaction
 * placeholders. Never logs or stores the actual secret values.
 */
export class CredentialRedactor {
  private readonly _config: ShieldXConfig

  /** Access the active configuration */
  get config(): ShieldXConfig { return this._config }

  constructor(config: ShieldXConfig) {
    this._config = config
  }

  /**
   * Redact all detected credentials from input.
   *
   * @param input - Text that may contain credentials
   * @returns Redacted text with count and types of secrets found
   */
  redact(input: string): RedactionResult {
    if (!input || input.length === 0) {
      return Object.freeze({
        redacted: '',
        foundSecrets: 0,
        secretTypes: Object.freeze([]),
      })
    }

    let redacted = input
    let totalFound = 0
    const typesFound = new Set<string>()

    for (const secret of SECRET_PATTERNS) {
      // Reset regex state for global patterns
      const pattern = new RegExp(secret.pattern.source, secret.pattern.flags)
      const matches = redacted.match(pattern)

      if (matches && matches.length > 0) {
        totalFound += matches.length
        typesFound.add(secret.type)

        // Handle password_in_url specially — only redact the password part
        if (secret.type === 'password_in_url') {
          redacted = redacted.replace(
            pattern,
            (match) => match.replace(/:([^@\s]{3,})@/, `:[REDACTED_PASSWORD]@`),
          )
        } else {
          redacted = redacted.replace(pattern, secret.redactionLabel)
        }
      }
    }

    return Object.freeze({
      redacted,
      foundSecrets: totalFound,
      secretTypes: Object.freeze([...typesFound].sort()),
    })
  }
}
