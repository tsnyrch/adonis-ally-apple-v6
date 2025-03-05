export { configure } from './configure.js'
import type { HttpContext } from '@adonisjs/core/http'
import { AppleDriver } from './src/apple.js'
import { AppleDriverConfig } from './src/types/main.js'

export function apple(config: AppleDriverConfig) {
  return (ctx: HttpContext) => new AppleDriver(ctx, config)
}
