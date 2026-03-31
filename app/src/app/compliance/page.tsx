'use client'

interface FrameworkSection {
  readonly name: string
  readonly description: string
  readonly coverage: number
  readonly color: string
  readonly items: readonly {
    readonly name: string
    readonly covered: boolean
    readonly note?: string
  }[]
}

const FRAMEWORKS: readonly FrameworkSection[] = [
  {
    name: 'MITRE ATLAS',
    description: 'Adversarial Threat Landscape for AI Systems -- mapping AI-specific attack techniques.',
    coverage: 78,
    color: '#3b82f6',
    items: [
      { name: 'AML.T0043 - Craft Adversarial Data', covered: true },
      { name: 'AML.T0044 - Full ML Model Access', covered: true },
      { name: 'AML.T0047 - ML Supply Chain Compromise', covered: true },
      { name: 'AML.T0048 - Command Injection via Prompt', covered: true },
      { name: 'AML.T0049 - System Prompt Extraction', covered: true },
      { name: 'AML.T0050 - Indirect Prompt Injection', covered: true },
      { name: 'AML.T0051 - LLM Jailbreak', covered: true },
      { name: 'AML.T0052 - Phishing via LLM', covered: false, note: 'Requires output monitoring integration' },
      { name: 'AML.T0053 - Data Poisoning', covered: false, note: 'Planned for v0.3' },
      { name: 'AML.T0054 - Model Denial of Service', covered: false, note: 'Rate limiting partial' },
    ],
  },
  {
    name: 'OWASP LLM Top 10 (2025)',
    description: 'Top 10 most critical vulnerabilities in LLM applications.',
    coverage: 85,
    color: '#22c55e',
    items: [
      { name: 'LLM01 - Prompt Injection', covered: true },
      { name: 'LLM02 - Insecure Output Handling', covered: true },
      { name: 'LLM03 - Training Data Poisoning', covered: false, note: 'Out of scope for runtime defense' },
      { name: 'LLM04 - Model Denial of Service', covered: true },
      { name: 'LLM05 - Supply Chain Vulnerabilities', covered: true },
      { name: 'LLM06 - Sensitive Information Disclosure', covered: true },
      { name: 'LLM07 - Insecure Plugin Design', covered: true },
      { name: 'LLM08 - Excessive Agency', covered: true },
      { name: 'LLM09 - Overreliance', covered: false, note: 'User education, not runtime' },
      { name: 'LLM10 - Model Theft', covered: false, note: 'Infrastructure-level concern' },
    ],
  },
  {
    name: 'EU AI Act',
    description: 'European Union regulation on artificial intelligence -- high-risk system requirements.',
    coverage: 72,
    color: '#8b5cf6',
    items: [
      { name: 'Art. 9 - Risk Management System', covered: true },
      { name: 'Art. 10 - Data Governance', covered: true },
      { name: 'Art. 11 - Technical Documentation', covered: true },
      { name: 'Art. 12 - Record-keeping / Logging', covered: true },
      { name: 'Art. 13 - Transparency', covered: true },
      { name: 'Art. 14 - Human Oversight', covered: true },
      { name: 'Art. 15 - Accuracy & Robustness', covered: true },
      { name: 'Art. 52 - Transparency Obligations', covered: false, note: 'Requires deployment configuration' },
      { name: 'Art. 62 - Reporting Obligations', covered: false, note: 'Incident export planned' },
      { name: 'Conformity Assessment', covered: false, note: 'Third-party audit required' },
    ],
  },
]

export default function CompliancePage() {
  return (
    <div>
      <div className="page-header">
        <h1>Compliance Center</h1>
        <p>Framework coverage and gap analysis for MITRE ATLAS, OWASP LLM Top 10, EU AI Act</p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
        {FRAMEWORKS.map((fw) => {
          const covered = fw.items.filter((i) => i.covered).length
          const total = fw.items.length
          const gaps = fw.items.filter((i) => !i.covered)

          return (
            <div key={fw.name} className="compliance-card">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h3>{fw.name}</h3>
                  <div className="text-sm text-secondary">{fw.description}</div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div className="coverage" style={{ color: fw.color }}>
                    {fw.coverage}%
                  </div>
                  <div className="text-xs text-muted">{covered}/{total} covered</div>
                </div>
              </div>

              {/* Progress bar */}
              <div className="progress-bar mb-4">
                <div
                  className="progress-fill"
                  style={{ width: `${fw.coverage}%`, background: fw.color }}
                />
              </div>

              {/* Items grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '4px 16px' }}>
                {fw.items.map((item) => (
                  <div
                    key={item.name}
                    className="flex items-center gap-2"
                    style={{ padding: '6px 0', fontSize: 13 }}
                  >
                    <span style={{ color: item.covered ? 'var(--success)' : 'var(--text-muted)', flexShrink: 0 }}>
                      {item.covered ? '\u2713' : '\u2717'}
                    </span>
                    <span style={{ color: item.covered ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                      {item.name}
                    </span>
                  </div>
                ))}
              </div>

              {/* Gaps */}
              {gaps.length > 0 && (
                <div style={{ marginTop: 16, paddingTop: 12, borderTop: '1px solid var(--border-color)' }}>
                  <div className="text-xs text-muted mb-2" style={{ textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.5px' }}>
                    Gaps & Recommendations
                  </div>
                  {gaps.map((gap) => (
                    <div key={gap.name} className="text-sm" style={{ padding: '3px 0', color: 'var(--text-secondary)' }}>
                      <span className="text-warning">{'\u25B8'}</span> {gap.name}
                      {gap.note && <span className="text-muted"> -- {gap.note}</span>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
