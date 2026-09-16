# Veil Go SDK

Generated from `docs/openapi/password-manager.openapi.json`. Do not handwrite clients.

The public module is `github.com/veilnyc/pwm-go`.

```bash
go get github.com/veilnyc/pwm-go
```

```go
package main

import (
	"context"
	"os"

	veilpwm "github.com/veilnyc/pwm-go"
)

func main() {
	cfg := veilpwm.NewConfiguration()
	cfg.Host = "veil.nyc"
	cfg.Scheme = "https"
	cfg.AddDefaultHeader("Authorization", "Bearer "+os.Getenv("PWM_OIDC_TOKEN"))
	client := veilpwm.NewAPIClient(cfg)
	_, _, _ = client.AgentAPI.ListItems(context.Background()).Execute()
}
```

The vault secret is never in the response.
