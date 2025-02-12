# Adonis Ally - Apple Sign In Driver

> adonis, adonis-ally, apple

This driver extends Adonis Ally and allows to integrate Apple Sign In.

FORKED FROM https://github.com/bitkidd/adonis-ally-apple/tree/main! THANKS TO HIM.

## Installation

```bash
npm install @wailroth/adonis-ally-apple-v6
# or
yarn add @wailroth/adonis-ally-apple-v6
```

As the package has been installed, you have to configure it by running a command:

```bash
node ace configure @wailroth/adonis-ally-apple-v6
```

Then open the `env.ts` file and paste the following code inside the `Env.rules` object.

```ts
APPLE_APP_ID: Env.schema.string(),
APPLE_TEAM_ID: Env.schema.string(),
APPLE_CLIENT_ID: Env.schema.string(),
APPLE_CLIENT_SECRET: Env.schema.string(),
```

And don't forget to add these variables to your `.env` and `.env.sample` files.

## Usage

Apple Driver environment variables have some specific usage:

- `APPLE_CLIENT_SECRET` - your app private key that you should download from [here](https://developer.apple.com/account/resources/authkeys/list)
- `APPLE_CLIENT_ID` - the id of the key you downloaded earlier, it can be found on the same page
- `APPLE_TEAM_ID` - you teams' id in Apple system, it can be found [here](https://developer.apple.com/account/#/membership)
- `APPLE_APP_ID` - your app idenifier, for ex: com.adonis.ally

For usage examples for Adonis Ally and its methods consult Adonis.js [official docs](https://docs.adonisjs.com/guides/auth/social).

