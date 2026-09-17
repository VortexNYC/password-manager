# Veil Go SDK

Generated from `docs/openapi/veil.openapi.json`. Do not handwrite clients.

The public module is `github.com/VortexNYC/veil/sdks/go`.

```bash
go get github.com/VortexNYC/veil/sdks/go
```

```go
package main

import (
	"context"
	"os"

	veil "github.com/VortexNYC/veil/sdks/go"
)

func main() {
	cfg := veil.NewConfiguration()
	cfg.Host = "veil.nyc"
	cfg.Scheme = "https"
	cfg.AddDefaultHeader("Authorization", "Bearer "+os.Getenv("VEIL_OIDC_TOKEN"))
	client := veil.NewAPIClient(cfg)
	_, _, _ = client.AgentAPI.ListItems(context.Background()).Execute()
}
```

The vault secret is never in the response.
