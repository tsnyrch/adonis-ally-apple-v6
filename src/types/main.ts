/**
 *
 * Access token returned by your driver implementation. An access
 * token must have "token" and "type" properties and you may
 * define additional properties (if needed)
 */

import { Oauth2AccessToken } from '@adonisjs/ally/types'

import { AllyUserContract, LiteralStringUnion } from '@adonisjs/ally/types'
import { DateTime } from 'luxon'

/**
 * Shape of Apple Access Token
 */
export type AppleAccessToken = Oauth2AccessToken & {
  id_token: string
  refreshToken: string
  expiresIn: number
  expiresAt: DateTime
}

/**
 * Shape of Apple Authorization Token Response
 * As returned by Apple authentication servers
 */
export type AppleAuthorizationTokenResponse = {
  /** A token used to access allowed data. */
  access_token: string
  /** It will always be Bearer. */
  token_type: 'Bearer'
  /** The amount of time, in seconds, before the access token expires. */
  expires_in: number
  /** used to regenerate (new) access tokens. */
  refresh_token: string
  /** A JSON Web Token that contains the user's identity information. */
  id_token: string
}

/**
 * Shape of the Apple decoded token
 * According to Apple's documentation for Sign in with Apple REST API
 */
export type AppleTokenDecoded = {
  /** The issuer-registered claim key, which has the value https://appleid.apple.com. */
  iss: string
  /** The unique identifier for the user. */
  sub: string
  /** Your client_id in your Apple Developer account. */
  aud: string
  /** The expiry time for the token. */
  exp: number
  /** The time the token was issued. */
  iat: number
  /** A String value used to associate a client session and an ID token. */
  nonce?: string
  /** A Boolean value that indicates whether the transaction is on a nonce-supported platform. */
  nonce_supported?: boolean
  /** The user's email address. */
  email: string
  /** A String or Boolean value that indicates whether the service has verified the email. */
  email_verified: 'true' | 'false' | boolean
  /** A String or Boolean value that indicates whether the email shared by the user is the proxy address. */
  is_private_email?: 'true' | 'false' | boolean
  /** Hash of the access token */
  at_hash?: string
  /** Real user status: 0: Unsupported, 1: Unknown, 2: LikelyReal */
  real_user_status?: number
  /** Present during 60-day transfer period after app transfer */
  transfer_sub?: string
  /** User information passed during authorization request */
  user?: {
    email?: string
    name?: {
      firstName: string
      lastName: string
    }
  }
  /** The time the user authenticated. */
  auth_time?: number
}

/**
 * Shape of Apple Webhook Event
 */
export type AppleWebhookEventType = {
  /** The type of event. */
  type: 'email-disabled' | 'email-enabled' | 'consent-revoked' | 'account-delete'
  /** The unique identifier for the user. */
  sub: string
  /** The time the event occurred. */
  event_time: number
  /** The email address for the user. Provided on `email-disabled` and `email-enabled` events only. */
  email?: string
  /** A String or Boolean value that indicates whether the email shared by the user is the proxy address.
      The value of this claim is always true because the email events relate only to the user's private relay service forwarding preferences.
      Provided on `email-disabled` and `email-enabled` events only. */
  is_private_email?: 'true' | 'false' | boolean
}

/**
 * Shape of Apple Webhook Token
 */
export type AppleWebhookToken = {
  /** The issuer-registered claim key, which has the value https://appleid.apple.com. */
  iss: string
  /** Your client_id in your Apple Developer account. */
  aud: string
  /** The expiry time for the token. This value is typically set to five minutes. */
  exp: number
  /** The time the token was issued. */
  iat: number
  /** The unique identifier for this token. */
  jti: string
  /** The event description. */
  events: AppleWebhookEventType
}

/**
 * Raw Webhook Token before event parsing
 */
export type RawAppleWebhookToken = {
  /** The issuer-registered claim key, which has the value https://appleid.apple.com. */
  iss: string
  /** Your client_id in your Apple Developer account. */
  aud: string
  /** The expiry time for the token. This value is typically set to five minutes. */
  exp: number
  /** The time the token was issued. */
  iat: number
  /** The unique identifier for this token. */
  jti: string
  /** The JSON-stringified event description. */
  events: string
}

/**
 * Allowed Apple Sign In scopes
 *
 * - 'email': Request the user's email address
 * - 'name': Request the user's name
 * - 'edu.users.read': For educational user data
 * - 'edu.classes.read': For educational class data
 */
export type AppleScopes = 'email' | 'name' | 'edu.users.read' | 'edu.classes.read'

/**
 * Configuration for Apple OAuth driver
 */
export type AppleDriverConfig = {
  driver: 'apple'
  clientId: string
  teamId: string
  keyId: string
  clientSecret: string
  callbackUrl: string
  scopes?: LiteralStringUnion<AppleScopes>[]
  disableCaching?: boolean
}

export interface AppleUserContract extends Omit<AllyUserContract<AppleAccessToken>, 'token'> {}
