# ShieldX — n8n Integration

Scan LLM input/output for prompt injection attacks directly in your n8n workflows.

## Installation

Copy `ShieldXNode.ts` (compiled to JS) into `~/.n8n/custom/` or register as a community node.

## Workflow Example

```
Webhook -> ShieldX (Scan Input) -> IF (shieldx.blocked) -> Response (Blocked)
                                                         -> LLM Node -> ShieldX (Scan Output) -> Response
```

## Node Configuration

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| Operation | Options | `scanInput` | `Scan Input` (pre-LLM) or `Scan Output` (post-LLM) |
| Input Field | String | `message` | JSON field path containing text to scan (dot-notation supported) |
| Threat Level Threshold | Options | `medium` | Minimum threat level: `low`, `medium`, `high`, `critical` |
| Block on Detection | Boolean | `true` | Stop the item from proceeding when a threat is detected |

## Output

Each item's JSON is enriched with a `shieldx` object:

```json
{
  "message": "User input here",
  "shieldx": {
    "blocked": false,
    "scanId": "550e8400-e29b-41d4-a716-446655440000",
    "detected": true,
    "threatLevel": "low",
    "killChainPhase": "initial_access",
    "action": "warn",
    "latencyMs": 3.42
  }
}
```

When `blocked: true`, the original text is preserved but the item is flagged for the workflow to handle (e.g., route to an error response instead of the LLM).

When sanitization is applied, the input field is replaced with the sanitized version.

## Dot-Notation Field Paths

The `Input Field` supports dot-notation for nested JSON:

- `message` — top-level field
- `data.content` — nested field
- `messages.0.content` — array access (by index)
