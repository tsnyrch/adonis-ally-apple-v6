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
 * Shape of the Apple decoded token
 * https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/incorporating_sign_in_with_apple_into_other_platforms
 */
export type AppleTokenDecoded = {
  iss: string
  aud: string
  exp: number
  iat: number
  sub: string
  at_hash: string
  email: string
  email_verified: 'true' | 'false'
  user?: {
    email?: string
    name?: {
      firstName: string
      lastName: string
    }
  }
  is_private_email: boolean
  auth_time: number
  nonce_supported: boolean
}

/**
 * Allowed Apple Sign In scopes
 */
export type AppleScopes = 'email' | 'string'

/**
 * Options available for Apple
 * @param appId App ID of your app
 * @param teamId Team ID of your Apple Developer Account
 * @param clientId Key ID, received from https://developer.apple.com/account/resources/authkeys/list
 * @param clientSecret Private key, downloaded from https://developer.apple.com/account/resources/authkeys/list
 */
export type AppleDriverConfig = {
  driver: 'apple'
  appId: string
  teamId: string
  clientId: string
  clientSecret: string
  callbackUrl: string
  scopes?: LiteralStringUnion<AppleScopes>[]
}

export interface AppleUserContract extends Omit<AllyUserContract<AppleAccessToken>, 'token'> {}
