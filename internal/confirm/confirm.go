// Package confirm is Touch ID at fill time. The native host prompts
// before a secret goes to the extension. Host.Confirm nil fails closed.
package confirm

import (
	"os"
	"strings"
)

// Enabled is Mac + PWM_FILL_TOUCHID not "0". Linux/Windows wait for 35–36.
func Enabled() bool {
	if os.Getenv("PWM_FILL_TOUCHID") == "0" {
		return false
	}
	return touchIDAvailable
}

// Action is the allow-line verb. "Veil wants to fill a card" → "fill a card".
func Action(reason string) string {
	s := strings.TrimSpace(reason)
	s = strings.TrimPrefix(s, "Veil wants to ")
	if s == "" {
		return "use Veil"
	}
	return s
}

func accountLabel() string {
	e := strings.TrimSpace(os.Getenv("PWM_LOGIN_EMAIL"))
	if e != "" {
		return e
	}
	return "Veil"
}

func interactive() bool {
	st, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

// CLIAccess is the Ghostty sheet: Allow {app} to get CLI access.
// Fill uses TouchID. Agents and PWM_FILL_TOUCHID=0 skip.
func CLIAccess() error {
	if !Enabled() || !interactive() {
		return nil
	}
	bundle := callerBundle()
	if bundle != "" && cliAllowed(bundle) {
		return nil
	}
	if err := TouchID("get CLI access"); err != nil {
		return err
	}
	if bundle != "" {
		cliRemember(bundle)
	}
	return nil
}
