# @vortex-api/veil

Generated TypeScript SDK for the Veil public API.

This package is generated from `docs/openapi/veil.openapi.json` by `pnpm run sdk:generate`.
It is MIT-licensed and published to the public npm registry.

```bash
pnpm add @vortex-api/veil
```

```ts
import { createClient, listItems, useItem } from "@vortex-api/veil";

const client = createClient({
  baseUrl: "https://veil.nyc",
  headers: { Authorization: `Bearer ${process.env.VEIL_OIDC_TOKEN}` },
});

const { data } = await listItems({ client });
await useItem({
  client,
  body: { item: "stripe", url: "https://api.stripe.com/v1/customers", method: "POST" },
});
```

The vault secret is never in the response.
