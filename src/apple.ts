/*
|--------------------------------------------------------------------------
| Apple OAuth driver for Adonis Ally
|--------------------------------------------------------------------------
|
| This driver implements Sign in with Apple REST API authentication for
| web and non-Apple platforms.
|
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
import { randomBytes } from 'node:crypto'
import {
  AppleAccessToken,
  AppleDriverConfig,
  AppleScopes,
  AppleTokenDecoded,
  AppleUserContract,
  AppleWebhookToken,
  RawAppleWebhookToken,
} from './types/main.js'

/**
 * Custom OAuth exception class for handling Apple OAuth specific errors
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

  static tokenVerificationFailed(message: string) {
    return new OauthException(`Token verification failed: ${message}`)
  }

  static refreshTokenInvalid() {
    return new OauthException('Refresh token is invalid or expired')
  }
}

/**
 * Apple OAuth Driver implementation for Adonis Ally
 */
export class AppleDriver
  extends Oauth2Driver<AppleAccessToken, AppleScopes>
  implements AllyDriverContract<AppleAccessToken, AppleScopes>
{
  /**
   * The base URL for Apple's authentication services
   */
  protected endpointUrl = 'https://appleid.apple.com'

  /**
   * The URL for the redirect request
   */
  protected authorizeUrl = 'https://appleid.apple.com/auth/authorize'

  /**
   * The URL to exchange the authorization code for the access token
   */
  protected accessTokenUrl = 'https://appleid.apple.com/auth/token'

  /**
   * The URL to fetch Apple's public keys for token verification
   */
  protected jwksUrl = 'https://appleid.apple.com/auth/keys'

  /**
   * The URL to revoke tokens
   */
  protected revokeUrl = 'https://appleid.apple.com/auth/revoke'

  /**
   * JWKS Client for Apple key verification
   */
  protected jwksClient: ReturnType<typeof jose.createRemoteJWKSet> | null = null

  /**
   * Cache for Apple's public keys
   */
  protected static appleKeysCache: Record<string, jose.KeyLike> = {}

  /**
   * Nonce for preventing replay attacks
   */
  protected nonce: string = randomBytes(16).toString('hex')

  /**
   * The param name for the authorization code
   */
  protected codeParamName = 'code'

  /**
   * The param name for the error
   */
  protected errorParamName = 'error'

  /**
   * Cookie name for storing the CSRF token
   */
  protected stateCookieName = 'apple_oauth_state'

  /**
   * Parameter name for the state
   */
  protected stateParamName = 'state'

  /**
   * Parameter name for sending the scopes
   */
  protected scopeParamName = 'scope'

  /**
   * The separator identifier for defining multiple scopes
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
     * Load state from the cookie
     */
    this.loadState()
  }

  /**
   * Initialize JWKS client for token verification
   */
  private async initializeJwksClient() {
    try {
      const jwks = jose.createRemoteJWKSet(new URL(this.jwksUrl))
      this.jwksClient = jwks
    } catch (error) {
      console.error('Failed to initialize JWKS client:', error)
    }
  }

  /**
   * Get Apple's public keys
   */
  private async getApplePublicKeys(
    options: { disableCaching?: boolean } = {}
  ): Promise<Record<string, jose.KeyLike>> {
    // If keys are cached and caching is not disabled, return them
    if (
      Object.keys(AppleDriver.appleKeysCache).length > 0 &&
      !options.disableCaching &&
      !this.config.disableCaching
    ) {
      return AppleDriver.appleKeysCache
    }

    try {
      const keysResponse = await fetch(this.jwksUrl, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      if (!keysResponse.ok) {
        throw new Error(`Failed to fetch Apple public keys: ${keysResponse.statusText}`)
      }

      const keysData: any = await keysResponse.json()

      // Parse and import each key
      const keysCache: Record<string, jose.KeyLike> = {}

      for (const key of keysData.keys) {
        try {
          const publicKey = await jose.importJWK(key)
          if ('type' in publicKey) {
            keysCache[key.kid] = publicKey as jose.KeyLike
          }
        } catch (error) {
          console.error(`Failed to import key ${key.kid}:`, error)
        }
      }

      // Cache keys if caching is not disabled
      if (!this.config.disableCaching && !options.disableCaching) {
        AppleDriver.appleKeysCache = keysCache
      }

      return keysCache
    } catch (error) {
      console.error('Error fetching Apple public keys:', error)
      throw error
    }
  }

  /**
   * Override getState to also check POST body for state parameter
   * This is needed because Apple uses form_post which puts state in POST body
   */
  getState(): string {
    const state = super.getState() || this.ctx.request.input(this.stateParamName) || ''
    return state
  }

  /**
   * Override stateMisMatch to handle form_post response mode
   * Uses more flexible state checking that works with POST requests
   */
  stateMisMatch(): boolean {
    // Get state from both POST body and query parameters
    const requestState =
      this.ctx.request.input(this.stateParamName) || this.ctx.request.qs()[this.stateParamName]

    const cookieState = this.ctx.request.cookie(this.stateCookieName)

    // No state in cookie means we didn't set one during redirect
    if (!cookieState) {
      return false
    }

    // If we have both cookie state and request state, they must match
    return requestState && cookieState ? requestState !== cookieState : false
  }

  /**
   * Override getCode to check both POST body and query parameters
   * This is needed for the form_post response mode
   */
  getCode(): string {
    return (
      this.ctx.request.input(this.codeParamName) || this.ctx.request.qs()[this.codeParamName] || ''
    )
  }

  /**
   * Configure the authorization redirect request
   */
  protected configureRedirectRequest(request: RedirectRequestContract<AppleScopes>) {
    // Define default scopes if none are provided
    const defaultScopes = ['email', 'name']

    // Use user-defined scopes or default ones
    request.scopes(this.config.scopes || defaultScopes)

    // Set required OAuth parameters
    request.param('client_id', this.config.clientId)
    request.param('response_type', 'code')
    request.param('response_mode', 'form_post')
    request.param('nonce', this.nonce)
    request.param('state', this.getState())
  }

  /**
   * Check if access was denied by the user
   */
  accessDenied(): boolean {
    const error = this.ctx.request.input('error') || this.ctx.request.qs()[this.errorParamName]
    return error === 'user_denied' || error === 'access_denied'
  }

  /**
   * Verify Apple ID token with proper validation as per Apple's documentation
   */
  protected async verifyToken(
    token: string,
    options: jose.JWTVerifyOptions = {}
  ): Promise<AppleTokenDecoded> {
    if (!this.jwksClient) {
      await this.initializeJwksClient()
    }

    const verifyOptions = {
      issuer: 'https://appleid.apple.com',
      audience: this.config.clientId,
      // Only include nonce if it was sent during authorization
      ...(this.nonce ? { nonce: this.nonce } : {}),
      ...options,
    }

    try {
      // First, try with JWKS client
      try {
        const { payload } = await jose
          .jwtVerify(token, this.jwksClient!, verifyOptions)
          .catch(async (error) => {
            // Handle multiple keys scenario
            if (error?.code === 'ERR_JWKS_MULTIPLE_MATCHING_KEYS') {
              const keys = await this.getApplePublicKeys()

              // Try each key until one works
              for (const [, publicKey] of Object.entries(keys)) {
                try {
                  return await jose.jwtVerify(token, publicKey, verifyOptions)
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

        // Additional verification steps according to Apple's docs
        const now = Math.floor(Date.now() / 1000)

        // Verify expiration time
        if (typeof payload.exp === 'number' && payload.exp < now) {
          throw new Error('Token has expired')
        }

        // Verify issued at time
        if (typeof payload.iat === 'number' && payload.iat > now) {
          throw new Error('Token issued at time is in the future')
        }

        // Verify issuer
        if (payload.iss !== 'https://appleid.apple.com') {
          throw new Error('Invalid token issuer')
        }

        return payload as unknown as AppleTokenDecoded
      } catch (joseError) {
        // Fallback to manual JWT verification with refreshed keys
        const keys = await this.getApplePublicKeys({ disableCaching: true })

        // Decode the token to get the key ID
        const decodedHeader = JWT.decode(token, { complete: true })?.header

        if (!decodedHeader || typeof decodedHeader !== 'object' || !('kid' in decodedHeader)) {
          throw new Error('Invalid token header')
        }

        const kid = decodedHeader.kid as string
        if (!kid || !keys[kid]) {
          throw new Error(`No matching key found for kid: ${kid}`)
        }

        // Export the key to JWK and convert to PEM format
        const keyAsPem = await jose.exportSPKI(keys[kid])

        // Manually verify the token
        const verifiedPayload = JWT.verify(token, keyAsPem, {
          algorithms: ['RS256'],
          issuer: 'https://appleid.apple.com',
          audience: this.config.clientId,
        })

        return verifiedPayload as AppleTokenDecoded
      }
    } catch (error) {
      throw OauthException.tokenVerificationFailed(error.message)
    }
  }

  /**
   * Verify Apple webhook token
   */
  async verifyWebhookToken(
    token: string,
    options: jose.JWTVerifyOptions = {}
  ): Promise<AppleWebhookToken> {
    try {
      const decodedToken = (await this.verifyToken(
        token,
        options
      )) as unknown as RawAppleWebhookToken

      // Parse events JSON string into object
      return {
        ...decodedToken,
        events:
          typeof decodedToken.events === 'string'
            ? JSON.parse(decodedToken.events)
            : decodedToken.events,
      } as unknown as AppleWebhookToken
    } catch (error) {
      throw OauthException.tokenVerificationFailed(
        `Webhook token verification failed: ${error.message}`
      )
    }
  }

  /**
   * Get access token from Apple
   */
  async accessToken(callback?: (request: ApiRequestContract) => void): Promise<AppleAccessToken> {
    /**
     * Check for errors in the request
     */
    if (this.hasError()) {
      throw OauthException.missingAuthorizationCode(this.codeParamName)
    }

    /**
     * Ensure state matches to prevent CSRF attacks
     */
    if (this.stateMisMatch()) {
      throw OauthException.stateMisMatch()
    }

    return this.getAccessToken((request) => {
      request.header('Content-Type', 'application/x-www-form-urlencoded')
      request.field('client_id', this.config.clientId)
      request.field('client_secret', this.config.clientSecret)
      request.field(this.codeParamName, this.getCode())
      request.field('grant_type', 'authorization_code')
      request.field('redirect_uri', this.config.callbackUrl)

      if (typeof callback === 'function') {
        callback(request)
      }
    })
  }

  /**
   * Refresh an expired access token
   */
  async refreshToken(
    refreshToken: string,
    callback?: (request: ApiRequestContract) => void
  ): Promise<AppleAccessToken> {
    if (!refreshToken) {
      throw OauthException.refreshTokenInvalid()
    }

    return this.getAccessToken((request) => {
      request.header('Content-Type', 'application/x-www-form-urlencoded')
      request.field('client_id', this.config.clientId)
      request.field('client_secret', this.config.clientSecret)
      request.field('refresh_token', refreshToken)
      request.field('grant_type', 'refresh_token')

      if (typeof callback === 'function') {
        callback(request)
      }
    })
  }

  /**
   * Revoke an access or refresh token
   */
  async revokeToken(
    token: string,
    tokenTypeHint: 'refresh_token' | 'access_token' = 'access_token'
  ): Promise<boolean> {
    if (!token) {
      throw new Error('Token is required for revocation')
    }

    const url = new URL(this.revokeUrl)

    const params = new URLSearchParams()
    params.append('client_id', this.config.clientId)
    params.append('client_secret', this.config.clientSecret)
    params.append('token', token)
    params.append('token_type_hint', tokenTypeHint)

    try {
      const response = await fetch(url.toString(), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params,
      })

      return response.ok
    } catch (error) {
      console.error('Error revoking token:', error)
      return false
    }
  }

  /**
   * Parse user information from the Apple ID token with support for additional claims
   */
  protected async getUserInfo(token: string): Promise<AppleUserContract> {
    const decodedUser = await this.verifyToken(token)
    const firstName = decodedUser?.user?.name?.firstName || ''
    const lastName = decodedUser?.user?.name?.lastName || ''

    // Build user object
    return {
      id: decodedUser.sub,
      avatarUrl: null,
      original: decodedUser,
      nickName: decodedUser.sub,
      name: `${firstName}${lastName ? ` ${lastName}` : ''}`,
      email: decodedUser.email,
      emailVerificationState:
        decodedUser.email_verified === 'true' || decodedUser.email_verified === true
          ? 'verified'
          : 'unverified',
    }
  }

  /**
   * Returns user details for the authenticated user
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
   * Find a user by their access token
   */
  async userFromToken(token: string) {
    const user = await this.getUserInfo(token)

    return {
      ...user,
      token: { token, type: 'bearer' as const },
    }
  }

  /**
   * Returns the redirect URL for Apple Sign In
   */
  getRedirectUrl(callback?: (request: RedirectRequestContract) => void) {
    const url = new URL(this.authorizeUrl)

    // Add required parameters
    url.searchParams.append('response_type', 'code')
    url.searchParams.append('client_id', this.config.clientId)
    url.searchParams.append('redirect_uri', this.config.callbackUrl)

    // Add scopes
    const scopes = this.config.scopes || ['email', 'name']
    url.searchParams.append('scope', scopes.join(' '))

    // Add state for CSRF protection
    const state = this.getState() || randomBytes(16).toString('hex')
    url.searchParams.append('state', state)

    // Add nonce for token verification
    url.searchParams.append('nonce', this.nonce)

    // Force form_post response mode when email scope is requested
    const responseMode = scopes.includes('email') ? 'form_post' : 'query'
    url.searchParams.append('response_mode', responseMode)

    // Allow callback to modify request if provided
    if (callback) {
      const request = {
        param: (key: string, value: string) => url.searchParams.set(key, value),
      } as RedirectRequestContract
      callback(request)
    }

    return url.toString()
  }
}
