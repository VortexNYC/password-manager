package publicapi

import _ "embed"

// Spec is the OpenAPI contract. SDKs, Blume /reference, and GET /openapi.json
// are this file. Do not handwrite clients.
//
//go:embed spec.json
var Spec []byte
