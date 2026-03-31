# ShieldX — Next.js Integration

Protect your Next.js 15 App Router LLM endpoints with ShieldX prompt injection defense.

## Middleware (recommended)

```typescript
// middleware.ts
import { shieldXMiddleware } from '@shieldx/core/integrations/nextjs'

export default shieldXMiddleware({
  scanners: { rules: true, entropy: true, unicode: true },
  logging: { level: 'warn' },
})

export const config = {
  matcher: '/api/chat/:path*',
}
```

## Route Handler HOC

```typescript
// app/api/chat/route.ts
import { withShieldX } from '@shieldx/core/integrations/nextjs'

async function handler(request: Request): Promise<Response> {
  const body = await request.json()
  // Your LLM call here...
  return Response.json({ message: 'Hello from the AI' })
}

export const POST = withShieldX(handler, {
  healing: { autoSanitize: true },
})
```

## Response Headers

All responses include:

| Header | Description |
|--------|-------------|
| `X-ShieldX-Threat-Level` | `none`, `low`, `medium`, `high`, `critical` |
| `X-ShieldX-Action` | `allow`, `sanitize`, `warn`, `block`, `reset`, `incident` |
| `X-ShieldX-Scan-Id` | UUID for feedback / audit trail |
| `X-ShieldX-Output-Threat-Level` | Threat level of the LLM output (if scanned) |

## Blocked Requests

When a request is blocked, the middleware returns HTTP 400:

```json
{
  "error": "Request blocked by security policy.",
  "scanId": "550e8400-e29b-41d4-a716-446655440000"
}
```

No detection details are exposed to the client.
