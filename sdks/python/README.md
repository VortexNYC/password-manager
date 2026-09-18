# vortex-api-veil

Generated from `docs/openapi/veil.openapi.json`. Do not handwrite clients.

```bash
pip install vortex-api-veil
```

```py
import os
import veil

configuration = veil.Configuration(host="https://veil.nyc")
configuration.access_token = os.environ["VEIL_OIDC_TOKEN"]
client = veil.ApiClient(configuration)
api = veil.AgentApi(client)
items = api.list_items()
api.use_item(veil.UseRequest(item="stripe", url="https://api.stripe.com/v1/customers"))
```

The vault secret is never in the response.
