import { describe, it, expect, beforeEach } from 'vitest'
import { CredentialRedactor } from '../../../src/sanitization/CredentialRedactor.js'
import { defaultConfig } from '../../../src/core/config.js'

describe('CredentialRedactor', () => {
  let redactor: CredentialRedactor

  beforeEach(() => {
    redactor = new CredentialRedactor(defaultConfig)
  })

  describe('API key detection', () => {
    it('should redact OpenAI sk- prefixed keys', () => {
      const input = 'My key is sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx'
      const result = redactor.redact(input)
      expect(result.redacted).toContain('[REDACTED_')
      expect(result.foundSecrets).toBeGreaterThan(0)
    })

    it('should redact GitHub ghp_ tokens', () => {
      const input = 'Token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678901'
      const result = redactor.redact(input)
      expect(result.redacted).toContain('[REDACTED_GITHUB_TOKEN]')
      expect(result.secretTypes).toContain('github_token')
    })

    it('should redact GitHub gho_ tokens', () => {
      const input = 'OAuth: gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678901'
      const result = redactor.redact(input)
      expect(result.redacted).toContain('[REDACTED_GITHUB_TOKEN]')
    })

    it('should redact AWS AKIA access key IDs', () => {
      const input = 'AWS key: AKIAIOSFODNN7EXAMPLE'
      const result = redactor.redact(input)
      expect(result.redacted).toContain('[REDACTED_AWS_KEY]')
      expect(result.secretTypes).toContain('aws_access_key')
    })

    it('should redact Google API keys', () => {
      // Pattern is AIza + exactly 35 chars of [A-Za-z0-9_-]
      const input = 'Google key: AIzaSyAbcdefghijklmnopqrstuvwxyz1234567'
      const result = redactor.redact(input)
      expect(result.redacted).toContain('[REDACTED_GOOGLE_KEY]')
      expect(result.secretTypes).toContain('google_api_key')
    })

    it('should redact Stripe keys', () => {
      const input = 'Stripe: sk_live_abc123def456ghi789jklm'
      const result = redactor.redact(input)
      expect(result.redacted).toContain('[REDACTED_STRIPE_KEY]')
      expect(result.secretTypes).toContain('stripe_key')
    })

    it('should redact Slack tokens', () => {
      const input = 'Slack: xoxb-1234567890-abc-defghijklm'
      const result = redactor.redact(input)
      expect(result.redacted).toContain('[REDACTED_SLACK_TOKEN]')
      expect(result.secretTypes).toContain('slack_token')
    })

    it('should redact Anthropic API keys', () => {
      const input = 'Anthropic: sk-ant-abcdefghijklmnopqrstuvwxyz012345678901234567'
      const result = redactor.redact(input)
      expect(result.redacted).toContain('[REDACTED_ANTHROPIC_KEY]')
      expect(result.secretTypes).toContain('anthropic_key')
    })

    it('should redact SendGrid keys', () => {
      const input = 'SendGrid: SG.abcdefghijklmnopqrstuv.wxyz0123456789abcdefghij'
      const result = redactor.redact(input)
      expect(result.redacted).toContain('[REDACTED_SENDGRID_KEY]')
      expect(result.secretTypes).toContain('sendgrid_key')
    })
  })

  describe('JWT token detection', () => {
    it('should redact JWT tokens', () => {
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
      const input = `Bearer ${jwt}`
      const result = redactor.redact(input)
      expect(result.foundSecrets).toBeGreaterThan(0)
      expect(result.redacted).toContain('[REDACTED_')
    })
  })

  describe('password in URL detection', () => {
    it('should redact passwords in URLs', () => {
      const input = 'Connect to postgres://admin:mysecretpass@localhost:5432/db'
      const result = redactor.redact(input)
      expect(result.redacted).not.toContain('mysecretpass')
      expect(result.foundSecrets).toBeGreaterThan(0)
    })
  })

  describe('email detection', () => {
    it('should redact email addresses', () => {
      const input = 'Contact john.doe@example.com for info'
      const result = redactor.redact(input)
      expect(result.redacted).toContain('[REDACTED_EMAIL]')
      expect(result.secretTypes).toContain('email_address')
    })

    it('should redact multiple emails', () => {
      const input = 'Send to alice@test.org and bob@company.net'
      const result = redactor.redact(input)
      expect(result.foundSecrets).toBeGreaterThanOrEqual(2)
    })
  })

  describe('database URL detection', () => {
    it('should redact PostgreSQL connection strings', () => {
      const input = 'DATABASE_URL=postgresql://user:pass@host:5432/dbname'
      const result = redactor.redact(input)
      expect(result.redacted).toContain('[REDACTED_')
      expect(result.foundSecrets).toBeGreaterThan(0)
    })

    it('should redact MongoDB connection strings', () => {
      const input = 'Use mongodb+srv://user:pass@cluster.example.net/mydb'
      const result = redactor.redact(input)
      expect(result.redacted).toContain('[REDACTED_')
    })
  })

  describe('private key detection', () => {
    it('should redact RSA private key blocks', () => {
      const input = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3...\n-----END RSA PRIVATE KEY-----'
      const result = redactor.redact(input)
      expect(result.redacted).toContain('[REDACTED_PRIVATE_KEY]')
      expect(result.secretTypes).toContain('private_key')
    })
  })

  describe('normal text passthrough', () => {
    it('should not redact normal English text', () => {
      const input = 'The quick brown fox jumps over the lazy dog.'
      const result = redactor.redact(input)
      expect(result.redacted).toBe(input)
      expect(result.foundSecrets).toBe(0)
      expect(result.secretTypes).toHaveLength(0)
    })

    it('should not redact technical discussion without secrets', () => {
      const input = 'We need to implement a REST API using Express.js with TypeScript strict mode.'
      const result = redactor.redact(input)
      expect(result.redacted).toBe(input)
      expect(result.foundSecrets).toBe(0)
    })

    it('should not redact short alphanumeric strings', () => {
      const input = 'The key concept is "abstraction" and the value is 42.'
      const result = redactor.redact(input)
      expect(result.foundSecrets).toBe(0)
    })
  })

  describe('redaction markers', () => {
    it('should use [REDACTED_*] marker format', () => {
      const input = 'Key: AKIAIOSFODNN7EXAMPLE and email user@test.com'
      const result = redactor.redact(input)
      const markers = result.redacted.match(/\[REDACTED_\w+\]/g) || []
      expect(markers.length).toBeGreaterThan(0)
      for (const marker of markers) {
        expect(marker).toMatch(/^\[REDACTED_\w+\]$/)
      }
    })
  })

  describe('edge cases', () => {
    it('should handle empty string', () => {
      const result = redactor.redact('')
      expect(result.redacted).toBe('')
      expect(result.foundSecrets).toBe(0)
    })

    it('should handle multiple different secret types in one input', () => {
      const input = 'AWS: AKIAIOSFODNN7EXAMPLE, Email: test@example.com, Stripe: sk_live_abcdefghijklmnopqrstu'
      const result = redactor.redact(input)
      expect(result.secretTypes.length).toBeGreaterThanOrEqual(2)
      expect(result.foundSecrets).toBeGreaterThanOrEqual(2)
    })

    it('should return frozen result', () => {
      const result = redactor.redact('test')
      expect(Object.isFrozen(result)).toBe(true)
    })
  })
})
