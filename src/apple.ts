/*
|--------------------------------------------------------------------------
| Ally Oauth driver
|--------------------------------------------------------------------------
|
| Make sure you through the code and comments properly and make necessary
| changes as per the requirements of your implementation.
|
*/

/**
|--------------------------------------------------------------------------
 *  Search keyword "YourDriver" and replace it with a meaningful name
|--------------------------------------------------------------------------
 */

import { Oauth2Driver } from '@adonisjs/ally'
import type {
  AllyDriverContract,
  ApiRequestContract,
  RedirectRequestContract,
} from '@adonisjs/ally/types'
import { HttpContext } from '@adonisjs/core/http'
import * as jose from 'jose'
import JWT from 'jsonwebtoken'
import {
  AppleAccessToken,
  AppleDriverConfig,
  AppleTokenDecoded,
  AppleUserContract,
} from './types/main.js'

import { AppleScopes } from './types/main.js'
/**
 * Custom OAuth exception class
 */
class OauthException extends Error {
  static missingAuthorizationCode(codeParamName: string) {
    return new OauthException(
      `Missing authorization code in the callback request. Make sure the "${codeParamName}" query string parameter exists`
    )
  }

  static stateMisMatch() {
    return new OauthException('State mismatch. Possible CSRF attack attempt')
  }
}

/**
 * Driver implementation. It is mostly configuration driven except the API call
 * to get user info.
 */
export class AppleDriver
  extends Oauth2Driver<AppleAccessToken, AppleScopes>
  implements AllyDriverContract<AppleAccessToken, AppleScopes>
{
  /**
   * The URL for the redirect request. The user will be redirected on this page
   * to authorize the request.
   */
  protected authorizeUrl = 'https://appleid.apple.com/auth/authorize'

  /**
   * The URL to hit to exchange the authorization code for the access token
   */
  protected accessTokenUrl = 'https://appleid.apple.com/auth/token'

  /**
   * JWKS Client for Apple key verification
   */
  protected jwksClient: ReturnType<typeof jose.createRemoteJWKSet> | null = null

  /**
   * The param name for the authorization code. Read the documentation of your oauth
   * provider and update the param name to match the query string field name in
   * which the oauth provider sends the authorization_code post redirect.
   */
  protected codeParamName = 'code'

  /**
   * The param name for the error. Read the documentation of your oauth provider and update
   * the param name to match the query string field name in which the oauth provider sends
   * the error post redirect
   */
  protected errorParamName = 'error'

  /**
   * Cookie name for storing the CSRF token. Make sure it is always unique. So a better
   * approach is to prefix the oauth provider name to `oauth_state` value. For example:
   * For example: "facebook_oauth_state"
   */
  protected stateCookieName = 'apple_oauth_state'

  /**
   * Parameter name to be used for sending and receiving the state from.
   * Read the documentation of your oauth provider and update the param
   * name to match the query string used by the provider for exchanging
   * the state.
   */
  protected stateParamName = 'state'

  /**
   * Parameter name for sending the scopes to the oauth provider.
   */
  protected scopeParamName = 'scope'

  /**
   * The separator indentifier for defining multiple scopes
   */
  protected scopesSeparator = ' '

  constructor(
    ctx: HttpContext,
    public config: AppleDriverConfig
  ) {
    super(ctx, config)

    /**
     * Initialize JWKS client
     */
    this.initializeJwksClient()

    /**
     * Extremely important to call the following method to clear the
     * state set by the redirect request.
     */
    this.loadState()
  }

  /**
   * Initialize JWKS client
   */
  private async initializeJwksClient() {
    const jwks = await jose.createRemoteJWKSet(new URL('https://appleid.apple.com/auth/keys'))
    this.jwksClient = jwks
  }

  /**
   * Optionally configure the authorization redirect request. The actual request
   * is made by the base implementation of "Oauth2" driver and this is a
   * hook to pre-configure the request.
   */
  protected configureRedirectRequest(request: RedirectRequestContract<AppleScopes>) {
    /**
     * Define user defined scopes or the default one's
     */
    request.scopes(this.config.scopes || ['email'])

    request.param('client_id', this.config.appId)
    request.param('response_type', 'code')
    request.param('response_mode', 'form_post')
    request.param('grant_type', 'authorization_code')
  }

  /**
   * Update the implementation to tell if the error received during redirect
   * means "ACCESS DENIED".
   */
  accessDenied(): boolean {
    return this.ctx.request.input('error') === 'user_denied'
  }

  /**
   * Get Apple Signing Key to verify token
   */
  protected async verifyToken(token: string) {
    if (!this.jwksClient) {
      await this.initializeJwksClient()
    }

    const options = {
      issuer: 'https://appleid.apple.com',
      audience: this.config.appId,
    }

    try {
      const { payload } = await jose
        .jwtVerify(token, this.jwksClient!, options)
        .catch(async (error) => {
          if (error?.code === 'ERR_JWKS_MULTIPLE_MATCHING_KEYS') {
            for await (const publicKey of error) {
              try {
                return await jose.jwtVerify(token, publicKey, options)
              } catch (innerError) {
                if (innerError?.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
                  continue
                }
                throw innerError
              }
            }
            throw new jose.errors.JWSSignatureVerificationFailed()
          }
          throw error
        })

      return payload as AppleTokenDecoded
    } catch (error) {
      throw new Error(`Token verification failed: ${error.message}`)
    }
  }

  /**
   * Generates Client Secret
   * https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
   * @returns clientSecret
   */
  protected generateClientSecret(): string {
    const clientSecret = JWT.sign({}, this.config.clientSecret, {
      algorithm: 'ES256',
      keyid: this.config.clientId,
      issuer: this.config.teamId,
      audience: 'https://appleid.apple.com',
      subject: this.config.appId,
      expiresIn: 60,
      header: { alg: 'ES256', kid: this.config.clientId },
    })
    return clientSecret
  }

  /**
   * Parses user info from the Apple Token
   */
  protected async getUserInfo(token: string): Promise<AppleUserContract> {
    const decodedUser = await this.verifyToken(token)
    const firstName = decodedUser?.user?.name?.firstName || ''
    const lastName = decodedUser?.user?.name?.lastName || ''

    return {
      id: decodedUser.sub,
      avatarUrl: null,
      original: null,
      nickName: decodedUser.sub,
      name: `${firstName}${lastName ? ` ${lastName}` : ''}`,
      email: decodedUser.email,
      emailVerificationState: decodedUser.email_verified === 'true' ? 'verified' : 'unverified',
    }
  }

  /**
   * Get access token
   */
  async accessToken(callback?: (request: ApiRequestContract) => void): Promise<AppleAccessToken> {
    /**
     * We expect the user to handle errors before calling this method
     */
    if (this.hasError()) {
      throw OauthException.missingAuthorizationCode(this.codeParamName)
    }

    /**
     * We expect the user to properly handle the state mis-match use case before
     * calling this method
     */
    if (this.stateMisMatch()) {
      throw OauthException.stateMisMatch()
    }

    return this.getAccessToken((request) => {
      request.header('Content-Type', 'application/x-www-form-urlencoded')
      request.field('client_id', this.config.appId)
      request.field('client_secret', this.generateClientSecret())
      request.field(this.codeParamName, this.getCode())

      if (typeof callback === 'function') {
        callback(request)
      }
    })
  }

  /**
   * Returns details for the authorized user
   */
  async user(callback?: (request: ApiRequestContract) => void) {
    const token = await this.accessToken(callback)
    const user = await this.getUserInfo(token.id_token)

    return {
      ...user,
      token,
    }
  }

  /**
   * Finds the user by the access token
   */
  async userFromToken(token: string) {
    const user = await this.getUserInfo(token)

    return {
      ...user,
      token: { token, type: 'bearer' as const },
    }
  }
}
