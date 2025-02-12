import type Configure from '@adonisjs/core/commands/configure'

/**
 * Configures the package
 */
export async function configure(command: Configure) {
  const codemods = await command.createCodemods()

  await codemods.defineEnvVariables({
    APPLE_APP_ID: '',
    APPLE_TEAM_ID: '',
    APPLE_CLIENT_ID: '',
    APPLE_CLIENT_SECRET: '',
  })

  await codemods.defineEnvValidations({
    variables: {
      APPLE_APP_ID: 'Env.schema.string()',
      APPLE_TEAM_ID: 'Env.schema.string()',
      APPLE_CLIENT_ID: 'Env.schema.string()',
      APPLE_CLIENT_SECRET: 'Env.schema.string()',
    },
    leadingComment: 'Variables for @wailroth/adonis-ally-apple-v6',
  })
}
