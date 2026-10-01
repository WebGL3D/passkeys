# :key: Passkeys Demo

This is a demo repository, intended for me to learn about how [passkeys](https://developer.mozilla.org/en-US/docs/Web/Security/Authentication/Passkeys) operate. The second goal of this project is learn more about [Rust](https://rust-lang.org).

Deployed on [Cloudflare Workers](https://www.cloudflare.com/products/workers/), for cost efficiency.

# :shushing_face: Secrets

Run these commands to generate, and set the secrets to run the app.

```sh
# Generate the keys
sh secrets.sh

# Save the keys to the Cloudflare worker
cat auth_private_key.pem | wrangler secret put JWT__PRIVATE_KEY
cat auth_public_key.pem | wrangler secret put JWT__PUBLIC_KEY
```

Obviously the public keys are not secret, but keeping them with the private keys makes it easier to comprehend what goes with what.
