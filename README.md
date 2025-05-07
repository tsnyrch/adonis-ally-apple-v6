# Adonis Ally - Apple Sign In Driver

This driver extends Adonis Ally and allows integration with Apple Sign In and Apple's Account & Organizational Data Sharing API.

FORKED FROM https://github.com/WailRoth/adonis-ally-apple-v6! THANKS TO THEM.

## Installation

```bash
npm install @tsnyrch/adonis-ally-apple-v6
# or
yarn add @tsnyrch/adonis-ally-apple-v6
```

After installation, configure the package by running:

```bash
node ace configure @tsnyrch/adonis-ally-apple-v6
```

## Configuration

### Environment Variables

Add the following environment variables to your `.env` file. These variables will be automatically added when running the configuration command:

```env
APPLE_CLIENT_ID=
APPLE_TEAM_ID=
APPLE_KEY_ID=
APPLE_CLIENT_SECRET=
```

- `APPLE_CLIENT_ID`: Your Apple Service ID identifier (e.g. "com.example.app")
- `APPLE_TEAM_ID`: Your Apple Developer Team ID
- `APPLE_KEY_ID`: The Key ID for the private key issued in your Apple Developer account
- `APPLE_CLIENT_SECRET`: The JWT client secret token that's required for API requests. **IMPORTANT: This is not your private key itself, but a JWT token you must generate using your private key.**

### About Apple Client Secret

⚠️ **IMPORTANT: Apple's client secret is different from most OAuth providers!**

Unlike other OAuth providers where the client secret is a fixed string, Apple requires a JWT token as the client secret. This JWT token:

1. **Has an expiration date** (maximum 6 months)
2. Must be signed with your private key downloaded from Apple Developer account
3. Must contain specific claims (iss, sub, aud, exp, iat)

#### How to Generate the Client Secret JWT

You can create the JWT token using a library like `jsonwebtoken`. Here's a robust function to generate your client secret:

```typescript
import jwt from 'jsonwebtoken'
import * as fs from 'fs'

/**
 * Generate an Apple client secret JWT
 */
function generateAppleClientSecret({
  clientId,
  teamId,
  keyId,
  privateKeyPath,
  expAfter = 15552000, // 180 days in seconds (6 months max)
}) {
  // Validate required parameters
  if (!clientId) throw new Error('clientId is required')
  if (!teamId) throw new Error('teamId is required')
  if (!keyId) throw new Error('keyId is required')
  if (!privateKeyPath) throw new Error('Either privateKey or privateKeyPath is required')
  if (privateKeyPath && !fs.existsSync(privateKeyPath))
    throw new Error(`Private key file not found at: ${privateKeyPath}`)

  // Prepare JWT claims
  const now = Math.floor(Date.now() / 1000)
  const claims = {
    iss: teamId,
    iat: now,
    exp: now + expAfter,
    aud: 'https://appleid.apple.com',
    sub: clientId,
  }

  // Set header with key ID
  const header = { alg: 'ES256', kid: keyId }

  // Get the private key content
  const key = privateKeyPath ? fs.readFileSync(privateKeyPath) : privateKey

  // Sign and return the JWT
  return jwt.sign(claims, key, { algorithm: 'ES256', header })
}

// Example usage:
const clientSecret = generateAppleClientSecret({
  clientId: 'com.example.app', // Your Service ID
  teamId: 'TEAM123456',        // Your Team ID
  keyId: 'ABC123DEFG',         // Your Key ID
  privateKeyPath: './AuthKey_ABC123DEFG.p8'
});

console.log('CLIENT SECRET: ', clientSecret) // Use this as your APPLE_CLIENT_SECRET
```

#### Production Recommendations

Since the JWT expires, you should implement a strategy to rotate it before expiration:

1. Set up a system to regenerate the token before it expires (e.g., every 5 months)
2. Store the newly generated token securely
3. Update your application's environment variables or configuration

For detailed instructions, refer to [Apple's official documentation](https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret).

### Setup in Ally Config

Register the driver in your `config/ally.ts` file:

```typescript
import { defineConfig } from '@adonisjs/ally'
import { apple } from '@tsnyrch/adonis-ally-apple-v6'

export default defineConfig({
  apple: apple({
    driver: 'apple',
    clientId: process.env.APPLE_CLIENT_ID!,
    teamId: process.env.APPLE_TEAM_ID!,
    keyId: process.env.APPLE_KEY_ID!,
    clientSecret: process.env.APPLE_CLIENT_SECRET!,
    callbackUrl: 'https://your-site.com/apple/callback',
    // Optional settings
    scopes: ['email', 'name'],
    disableCaching: false,
  }),
})
```

## Usage

### Basic Authentication Flow

```typescript
// In your routes file
Route.get('/apple/redirect', async ({ ally }) => {
  return ally.use('apple').redirect()
})

Route.get('/apple/callback', async ({ ally, response }) => {
  try {
    const apple = ally.use('apple')
    
    if (apple.accessDenied()) {
      return 'Access was denied'
    }
    
    // User has granted access
    const user = await apple.user()
    
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      emailVerificationState: user.emailVerificationState,
      token: user.token,
    }
  } catch (error) {
    console.error(error)
    return response.status(500).send('Authentication failed')
  }
})
```

### Manual Construction of Auth URL

If you need more control over the redirect URL:

```typescript
import { apple } from '@tsnyrch/adonis-ally-apple-v6'

// Define your config
const appleConfig = {
  driver: 'apple',
  clientId: 'YOUR_CLIENT_ID',
  teamId: 'YOUR_TEAM_ID',
  keyId: 'YOUR_KEY_ID',
  clientSecret: 'YOUR_JWT_CLIENT_SECRET', // The JWT token, not your private key
  callbackUrl: 'https://your-site.com/apple/callback',
}

// In your controller
export default class AppleAuthController {
  public async redirect({ response }) {
    const appleDriver = apple(appleConfig)({ request, response })
    const redirectUrl = appleDriver.getRedirectUrl()
    
    return response.redirect(redirectUrl)
  }
}
```

### Refreshing Tokens

Apple access tokens are short-lived. Use the refresh token to get a new access token:

```typescript
const appleDriver = ally.use('apple')
try {
  const refreshedToken = await appleDriver.refreshToken(user.token.refreshToken)
  // Store the new tokens
} catch (error) {
  console.error('Token refresh failed', error)
  // Handle refresh failure
}
```

### Revoking Tokens

When a user wishes to disconnect their Apple account:

```typescript
const appleDriver = ally.use('apple')
try {
  // Revoke the access token
  await appleDriver.revokeToken(user.token.token)
  
  // Or revoke the refresh token
  await appleDriver.revokeToken(user.token.refreshToken, 'refresh_token')
} catch (error) {
  console.error('Token revocation failed', error)
}
```

### Handling Apple Webhooks

Apple sends server-to-server notifications for events like:
- Email address changes (`email-enabled`, `email-disabled`)
- Account deletion (`account-delete`)
- Consent revocation (`consent-revoked`)

To verify and process these webhook events:

```typescript
import { AppleWebhookToken } from '@tsnyrch/adonis-ally-apple-v6'

// In your webhook controller
export default class AppleWebhookController {
  public async handle({ request, response }) {
    try {
      const token = request.input('token')
      const appleDriver = ally.use('apple')
      
      // Verify the webhook token
      const webhookData = await appleDriver.verifyWebhookToken(token)
      
      // Handle different event types
      switch (webhookData.events.type) {
        case 'email-disabled':
          // Handle private email relay disabled
          break
        case 'email-enabled':
          // Handle private email relay enabled
          break
        case 'consent-revoked':
          // Handle user revoked permissions
          break
        case 'account-delete':
          // Handle account deletion request
          break
      }
      
      return response.noContent()
    } catch (error) {
      console.error('Webhook verification failed', error)
      return response.status(400).send('Invalid webhook payload')
    }
  }
}
```

## API Reference

### Driver Methods

- `redirect()` - Redirects to Apple's authorization page
- `getRedirectUrl(callback?)` - Returns the authorization URL
- `user(callback?)` - Gets user details after successful authentication
- `accessToken(callback?)` - Gets the access token from the authorization code
- `refreshToken(refreshToken, callback?)` - Refreshes an expired access token
- `revokeToken(token, tokenTypeHint?)` - Revokes an access or refresh token
- `verifyWebhookToken(token, options?)` - Verifies Apple webhook notifications
- `userFromToken(token)` - Gets user details from an ID token

### Token Types

- `AppleAccessToken` - The access token returned by authentication
- `AppleTokenDecoded` - The decoded ID token with user information
- `AppleWebhookToken` - Webhook notification token from Apple
- `AppleAuthorizationTokenResponse` - Raw response from Apple's token endpoint

## Security Considerations

This driver implements several security best practices:
- CSRF protection with state parameter
- JWT token validation with proper key rotation
- Nonce verification to prevent replay attacks
- Support for Apple's private email relay service

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT


