export { configure } from './configure.js'
import type { HttpContext } from '@adonisjs/core/http'
import { AppleDriver } from './src/apple.js'
import type {
  AppleAccessToken,
  AppleDriverConfig,
  AppleTokenDecoded,
  AppleWebhookToken,
} from './src/types/main.js'

export function apple(config: AppleDriverConfig): (ctx: HttpContext) => AppleDriver {
  return (ctx: HttpContext) => new AppleDriver(ctx, config)
}

// Export types for convenience
export type { AppleAccessToken, AppleDriverConfig, AppleTokenDecoded, AppleWebhookToken }
