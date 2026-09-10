# Vortex Password Manager TypeScript SDK

Generated from `docs/openapi/password-manager.openapi.json`. Do not handwrite clients.

```ts
import { createClient, listItems, useItem } from "@vortex-api/pwm-sdk";

const client = createClient({
  baseUrl: "https://pwm.vortex.nyc",
  headers: { Authorization: `Bearer ${process.env.PWM_OIDC_TOKEN}` },
});

const { data } = await listItems({ client });
await useItem({
  client,
  body: { item: "stripe", url: "https://api.stripe.com/v1/customers", method: "POST" },
});
```

The vault secret is never in the response.
