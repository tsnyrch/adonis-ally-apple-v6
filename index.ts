export { configure } from './configure.js'
import type { HttpContext } from '@adonisjs/core/http'
import type { AppleDriverConfig } from './src/apple.js'
import { AppleDriver } from './src/apple.js'

export function apple(config: AppleDriverConfig) {
  return (ctx: HttpContext) => new AppleDriver(ctx, config)
}
