package fill

import (
	"os"
	"path/filepath"
)

func Install(bin, vaultHome, userHome string) error {
	if err := os.MkdirAll(vaultHome, 0o700); err != nil {
		return err
	}
	shim := filepath.Join(vaultHome, "native-host")
	if err := os.WriteFile(shim, []byte(Shim(bin, vaultHome)), 0o755); err != nil {
		return err
	}
	chromeDir := filepath.Join(userHome, "Library/Application Support/Google/Chrome/NativeMessagingHosts")
	if err := os.MkdirAll(chromeDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(chromeDir, NativeHostName+".json"), ManifestChrome(shim), 0o644); err != nil {
		return err
	}
	ffDir := filepath.Join(userHome, "Library/Application Support/Mozilla/NativeMessagingHosts")
	if err := os.MkdirAll(ffDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(ffDir, NativeHostName+".json"), ManifestFirefox(shim), 0o644)
}
