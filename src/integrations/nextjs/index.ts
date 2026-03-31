/**
 * Next.js 15 App Router integration for ShieldX.
 *
 * Provides middleware and route handler wrappers that automatically
 * scan LLM input/output for prompt injection attacks.
 *
 * @example
 * ```typescript
 * // middleware.ts
 * import { shieldXMiddleware } from '@shieldx/core/integrations/nextjs'
 * export default shieldXMiddleware()
 * ```
 */

export { shieldXMiddleware, withShieldX } from './middleware.js'
