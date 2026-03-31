# ShieldX — Anthropic Integration

Protect your Anthropic API calls with ShieldX prompt injection defense.

## Usage

```typescript
import { ShieldX } from '@shieldx/core'
import { createAnthropicClient } from '@shieldx/core/integrations/anthropic'

const shield = new ShieldX()
await shield.initialize()

const anthropic = createAnthropicClient({
  apiKey: process.env.ANTHROPIC_API_KEY,
  shieldx: shield,
})

const response = await anthropic.createMessage({
  model: 'claude-sonnet-4-20250514',
  max_tokens: 1024,
  messages: [
    { role: 'user', content: 'What is the meaning of life?' },
  ],
})

// Access response content
for (const block of response.content) {
  if (block.type === 'text') {
    console.log(block.text)
  }
}

// Check ShieldX results
if (response.shieldx?.detected) {
  console.warn('Threat detected:', response.shieldx.threatLevel)
  console.warn('Action taken:', response.shieldx.action)
}
```

## Features

- Scans all user messages before the API call
- Scans response content after the API call
- Blocks malicious requests with a safe fallback response
- Filters compromised LLM outputs
- Zero dependency on `@anthropic-ai/sdk` (uses native fetch)
- Full pass-through of Anthropic API parameters

## Blocked Requests

When ShieldX blocks a request:

```json
{
  "id": "msg_shieldx_blocked_...",
  "type": "message",
  "role": "assistant",
  "content": [{ "type": "text", "text": "Request blocked by security policy." }],
  "shieldx": { "detected": true, "threatLevel": "high", "action": "block", ... }
}
```
