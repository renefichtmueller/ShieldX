/**
 * Structured logging for ShieldX using Pino.
 */

import pino from 'pino'

interface LoggerConfig {
  readonly level: 'silent' | 'error' | 'warn' | 'info' | 'debug'
  readonly structured: boolean
  readonly incidentLog: boolean
}

/** Create a configured Pino logger instance */
export function createLogger(config: LoggerConfig): pino.Logger {
  return pino({
    name: 'shieldx',
    level: config.level,
    ...(config.structured
      ? {}
      : {
          transport: {
            target: 'pino/file',
            options: { destination: 1 }, // stdout
          },
        }),
  })
}

/** Create a child logger with additional context */
export function createChildLogger(
  parent: pino.Logger,
  context: Record<string, unknown>,
): pino.Logger {
  return parent.child(context)
}
