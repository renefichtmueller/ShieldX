'use client'

const CONFIG = {
  thresholds: {
    low: 0.3,
    medium: 0.5,
    high: 0.7,
    critical: 0.9,
  },
  scanners: {
    rules: true,
    sentinel: false,
    constitutional: false,
    embedding: false,
    embeddingAnomaly: false,
    entropy: true,
    yara: false,
    attention: false,
    canary: true,
    indirect: true,
    selfConsciousness: false,
    crossModel: false,
    behavioral: true,
    unicode: true,
    tokenizer: true,
    compressedPayload: true,
  },
  healing: {
    enabled: true,
    autoSanitize: true,
    sessionReset: true,
  },
  learning: {
    enabled: true,
    storageBackend: 'memory',
    feedbackLoop: true,
    communitySync: false,
    driftDetection: true,
    activelearning: true,
    attackGraph: true,
  },
  behavioral: {
    enabled: true,
    baselineWindow: 100,
    driftThreshold: 0.3,
    intentTracking: true,
    conversationTracking: true,
    contextIntegrity: true,
    memoryIntegrity: false,
    bayesianTrustScoring: false,
  },
  mcpGuard: {
    enabled: false,
    validateToolCalls: true,
    privilegeCheck: true,
    toolChainGuard: true,
    resourceGovernor: true,
    decisionGraph: false,
    manifestVerification: false,
  },
  compliance: {
    mitreAtlas: true,
    owaspLlm: true,
    euAiAct: true,
  },
  logging: {
    level: 'info',
    structured: true,
    incidentLog: true,
  },
}

function renderValue(value: unknown): { text: string; className: string } {
  if (typeof value === 'boolean') {
    return {
      text: value ? 'enabled' : 'disabled',
      className: value ? 'config-value enabled' : 'config-value disabled',
    }
  }
  return { text: String(value), className: 'config-value' }
}

export default function ConfigPage() {
  return (
    <div>
      <div className="page-header">
        <h1>Configuration</h1>
        <p>Current ShieldX defense pipeline configuration (read-only)</p>
      </div>

      {Object.entries(CONFIG).map(([section, values]) => (
        <div key={section} className="config-section">
          <h3>{section}</h3>
          {typeof values === 'object' && values !== null ? (
            Object.entries(values).map(([key, val]) => {
              const { text, className } = renderValue(val)
              return (
                <div key={key} className="config-row">
                  <span className="config-key">{key}</span>
                  <span className={className}>{text}</span>
                </div>
              )
            })
          ) : (
            <div className="config-row">
              <span className="config-key">{section}</span>
              <span className="config-value">{String(values)}</span>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
