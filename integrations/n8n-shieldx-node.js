/**
 * ShieldX n8n Community Node
 *
 * Scans prompts through the ShieldX proxy before sending to LLMs.
 * Add this as a custom node in n8n.
 *
 * Setup:
 * 1. Copy to ~/.n8n/custom/nodes/ShieldX.node.js
 * 2. Set SHIELDX_PROXY_URL in n8n environment (default: http://localhost:11435)
 * 3. Add ShieldX node BEFORE any AI/LLM node in your workflow
 *
 * The node scans input text and either passes it through (clean)
 * or blocks it (threat detected), based on the configured action.
 */

module.exports = {
  description: {
    displayName: 'ShieldX',
    name: 'shieldX',
    group: ['transform'],
    version: 1,
    description: 'Scan prompts for injection attacks before sending to LLMs',
    defaults: { name: 'ShieldX' },
    inputs: ['main'],
    outputs: ['main'],
    properties: [
      {
        displayName: 'Input Field',
        name: 'inputField',
        type: 'string',
        default: 'text',
        description: 'The field name containing the text to scan',
      },
      {
        displayName: 'Proxy URL',
        name: 'proxyUrl',
        type: 'string',
        default: 'http://localhost:11435',
        description: 'ShieldX proxy URL',
      },
      {
        displayName: 'On Threat',
        name: 'onThreat',
        type: 'options',
        options: [
          { name: 'Block (stop workflow)', value: 'block' },
          { name: 'Warn (add flag, continue)', value: 'warn' },
          { name: 'Log Only', value: 'log' },
        ],
        default: 'block',
        description: 'Action when threat is detected',
      },
      {
        displayName: 'Min Threat Level',
        name: 'minThreatLevel',
        type: 'options',
        options: [
          { name: 'Low', value: 'low' },
          { name: 'Medium', value: 'medium' },
          { name: 'High', value: 'high' },
          { name: 'Critical', value: 'critical' },
        ],
        default: 'medium',
        description: 'Minimum threat level to trigger action',
      },
    ],
  },

  async execute() {
    const items = this.getInputData()
    const inputField = this.getNodeParameter('inputField', 0)
    const proxyUrl = this.getNodeParameter('proxyUrl', 0)
    const onThreat = this.getNodeParameter('onThreat', 0)
    const minLevel = this.getNodeParameter('minThreatLevel', 0)

    const LEVEL_ORDER = ['none', 'low', 'medium', 'high', 'critical']
    const minIdx = LEVEL_ORDER.indexOf(minLevel)

    const results = []

    for (let i = 0; i < items.length; i++) {
      const item = items[i]
      const input = item.json[inputField] || ''

      if (!input) {
        results.push(item)
        continue
      }

      try {
        const response = await this.helpers.httpRequest({
          method: 'POST',
          url: `${proxyUrl}/shieldx/scan`,
          body: { input },
          headers: { 'Content-Type': 'application/json' },
          timeout: 5000,
        })

        const threatIdx = LEVEL_ORDER.indexOf(response.threatLevel || 'none')
        const isAboveThreshold = threatIdx >= minIdx

        // Add scan metadata to item
        item.json.shieldx = {
          scanned: true,
          detected: response.detected || false,
          threatLevel: response.threatLevel || 'none',
          killChainPhase: response.killChainPhase || 'none',
          action: response.action || 'allow',
          matchedPatterns: response.matchedPatterns || [],
          latencyMs: response.latencyMs || 0,
        }

        if (response.detected && isAboveThreshold) {
          if (onThreat === 'block') {
            throw new Error(
              `ShieldX blocked: ${response.threatLevel} threat detected ` +
              `(${response.killChainPhase}). Patterns: ${(response.matchedPatterns || []).join(', ')}`
            )
          }
          // warn or log — continue with flag
          item.json.shieldx.blocked = onThreat === 'block'
        }

        results.push(item)
      } catch (err) {
        if (err.message?.startsWith('ShieldX blocked')) throw err
        // Proxy unavailable — fail open
        console.warn('[ShieldX] Proxy unavailable, failing open:', err.message)
        item.json.shieldx = { scanned: false, error: 'Proxy unavailable' }
        results.push(item)
      }
    }

    return [results]
  },
}
