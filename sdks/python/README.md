# veil-pwm-sdk

Generated from `docs/openapi/password-manager.openapi.json`. Do not handwrite clients.

```bash
pip install veil-pwm-sdk
```

```py
import os
import veil_pwm

configuration = veil_pwm.Configuration(host="https://veil.nyc")
configuration.access_token = os.environ["PWM_OIDC_TOKEN"]
client = veil_pwm.ApiClient(configuration)
api = veil_pwm.AgentApi(client)
items = api.list_items()
api.use_item(veil_pwm.UseRequest(item="stripe", url="https://api.stripe.com/v1/customers"))
```

The vault secret is never in the response.
