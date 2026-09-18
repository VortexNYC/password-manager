// Package envcompat bridges the legacy PWM_* environment to VEIL_* once at startup.
package envcompat

import (
	"os"
	"strings"
)

// BridgeLegacy copies every PWM_FOO into VEIL_FOO when VEIL_FOO is unset.
// Call it first in main so the rest of the process only reads VEIL_*.
func BridgeLegacy() {
	for _, e := range os.Environ() {
		k, v, ok := strings.Cut(e, "=")
		if !ok || !strings.HasPrefix(k, "PWM_") {
			continue
		}
		nk := "VEIL_" + k[len("PWM_"):]
		if os.Getenv(nk) == "" {
			_ = os.Setenv(nk, v)
		}
	}
}
