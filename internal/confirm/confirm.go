// Package confirm is Touch ID at fill time. The native host prompts
// before a secret goes to the extension. Host.Confirm nil fails closed.
package confirm

import "os"

// Enabled is Mac + PWM_FILL_TOUCHID not "0". Linux/Windows wait for 35–36.
func Enabled() bool {
	if os.Getenv("PWM_FILL_TOUCHID") == "0" {
		return false
	}
	return touchIDAvailable
}
