# ShieldX — Ollama Integration

Protect your local Ollama LLM with ShieldX prompt injection defense.

## Usage

```typescript
import { ShieldX } from '@shieldx/core'
import { createOllamaClient } from '@shieldx/core/integrations/ollama'

const shield = new ShieldX({
  mcpGuard: { ollamaEndpoint: 'http://localhost:11434' },
})
await shield.initialize()

const ollama = createOllamaClient({
  endpoint: 'http://localhost:11434',
  model: 'llama3.2',
  shieldx: shield,
})

// Chat (multi-turn)
const chatResult = await ollama.chat({
  messages: [
    { role: 'system', content: 'You are a helpful assistant.' },
    { role: 'user', content: 'What is the capital of France?' },
  ],
})

console.log(chatResult.message.content)
if (chatResult.shieldx?.detected) {
  console.warn('Threat detected:', chatResult.shieldx.threatLevel)
}

// Generate (single prompt)
const genResult = await ollama.generate({
  prompt: 'Explain quantum computing in simple terms.',
})

console.log(genResult.response)

// Embeddings (bypasses ShieldX)
const embedResult = await ollama.embeddings({
  prompt: 'Some text to embed',
})

console.log('Embedding dimensions:', embedResult.embedding.length)
```

## Blocked Requests

When ShieldX detects a prompt injection attack:

- **chat**: Returns `{ message: { content: 'Request blocked by security policy.' }, shieldx: ... }`
- **generate**: Returns `{ response: 'Request blocked by security policy.', shieldx: ... }`

The `shieldx` field contains the full `ShieldXResult` for inspection.
