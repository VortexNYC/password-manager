package fill

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeHostArgsRewritesChromeLaunch(t *testing.T) {
	got := NativeHostArgs([]string{"/vault/" + HostFile, ChromeOrigin()})
	if len(got) != 2 || got[1] != "fill" {
		t.Fatalf("%v", got)
	}
	jsonHost := NativeHostArgs([]string{"/vault/" + HostFile, JSONChromeOrigin()})
	if len(jsonHost) != 2 || jsonHost[1] != "fill" {
		t.Fatalf("%v", jsonHost)
	}
	plain := NativeHostArgs([]string{"password-manager", "item", "list"})
	if len(plain) != 3 || plain[1] != "item" {
		t.Fatalf("%v", plain)
	}
}

func TestNativeHostArgsBindsHomeToBinaryDir(t *testing.T) {
	t.Setenv("PWM_HOME", "/Users/someone/.password-manager")
	dir := t.TempDir()
	bin := filepath.Join(dir, HostFile)
	got := NativeHostArgs([]string{bin, JSONChromeOrigin()})
	if len(got) != 2 || got[1] != "fill" {
		t.Fatalf("%v", got)
	}
	if os.Getenv("PWM_HOME") != dir {
		t.Fatalf("PWM_HOME=%s want %s", os.Getenv("PWM_HOME"), dir)
	}
}

func TestNativeHostArgsStripsAgentShellEnv(t *testing.T) {
	t.Setenv("PWM_FILL_TOUCHID", "0")
	t.Setenv("PWM_AGENT", "cursor")
	t.Setenv("PWM_OIDC_TOKEN_FILE", "/tmp/agent.jwt")
	t.Setenv("PWM_OIDC_TOKEN", "no")
	dir := t.TempDir()
	bin := filepath.Join(dir, HostFile)
	NativeHostArgs([]string{bin, JSONChromeOrigin()})
	if os.Getenv("PWM_FILL_TOUCHID") != "" {
		t.Fatal("PWM_FILL_TOUCHID leaked from the launching shell")
	}
	if os.Getenv("PWM_AGENT") != "" || os.Getenv("PWM_OIDC_TOKEN_FILE") != "" || os.Getenv("PWM_OIDC_TOKEN") != "" {
		t.Fatal("agent env leaked into the native host")
	}
}

func TestApplyHostConfigSetsBlankEnv(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHostConfig(dir, HostConfig{Origin: "https://veil.nyc", Home: dir}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWM_ORIGIN", "")
	t.Setenv("PWM_HOME", "")
	if err := ApplyHostConfig(dir); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PWM_ORIGIN") != "https://veil.nyc" {
		t.Fatalf("%s", os.Getenv("PWM_ORIGIN"))
	}
	if os.Getenv("PWM_HOME") != dir {
		t.Fatalf("%s", os.Getenv("PWM_HOME"))
	}
}

func TestApplyHostConfigDoesNotOverrideEnv(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHostConfig(dir, HostConfig{Origin: "https://veil.nyc"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWM_ORIGIN", "https://example.invalid")
	if err := ApplyHostConfig(dir); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PWM_ORIGIN") != "https://example.invalid" {
		t.Fatal("overrode PWM_ORIGIN")
	}
}

func TestApplyHostConfigDebug(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHostConfig(dir, HostConfig{Debug: true}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWM_FILL_DEBUG", "")
	if err := ApplyHostConfig(dir); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PWM_FILL_DEBUG") != "1" {
		t.Fatal("debug not applied")
	}
}

func TestApplyHostConfigTouchIDOff(t *testing.T) {
	dir := t.TempDir()
	off := false
	if err := WriteHostConfig(dir, HostConfig{TouchID: &off}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWM_FILL_TOUCHID", "")
	if err := ApplyHostConfig(dir); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PWM_FILL_TOUCHID") != "0" {
		t.Fatal("touch id not off")
	}
}

func TestHostConfigMissingIsOK(t *testing.T) {
	if err := ApplyHostConfig(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestCopyExecutableWritesHostBytes(t *testing.T) {
	src := filepath.Join(t.TempDir(), "bin")
	dst := filepath.Join(t.TempDir(), HostFile)
	if err := os.WriteFile(src, []byte("pwm-host-binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyExecutable(src, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if bytesHasShebang(got) {
		t.Fatal("copied a script")
	}
}

func bytesHasShebang(b []byte) bool {
	return len(b) >= 2 && b[0] == '#' && b[1] == '!'
}
