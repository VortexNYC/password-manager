# vortex-pwm-sdk

Generated from `docs/openapi/password-manager.openapi.json`. Do not handwrite clients.

```bash
pip install vortex-pwm-sdk
```

```py
import os
import vortex_pwm

configuration = vortex_pwm.Configuration(host="https://pwm.vortex.nyc")
configuration.access_token = os.environ["PWM_OIDC_TOKEN"]
client = vortex_pwm.ApiClient(configuration)
api = vortex_pwm.AgentApi(client)
items = api.list_items()
api.use_item(vortex_pwm.UseRequest(item="stripe", url="https://api.stripe.com/v1/customers"))
```

The vault secret is never in the response.
