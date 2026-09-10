package material

import (
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

const seed = "JBSWY3DPEHPK3PXP"

func TestPackFileRoundTrip(t *testing.T) {
	raw, err := PackFile("note.txt", "text/plain", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := FileBytes(Unpack(raw))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("%q", got)
	}
	if _, err := PackFile("x", "", make([]byte, MaxFile+1)); err == nil {
		t.Fatal("oversize")
	}
}

func TestUnpackRawTokenCompat(t *testing.T) {
	env := Unpack([]byte("sk_live_plain"))
	if env.Token != "sk_live_plain" || env.TOTP != "" {
		t.Fatalf("%+v", env)
	}
}

func TestWithLoginUpgradesPlainToken(t *testing.T) {
	raw, err := WithLogin([]byte("sk_live_plain"), "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	env := Unpack(raw)
	if env.V != 1 || env.Token != "sk_live_plain" || env.Login != "user@example.com" {
		t.Fatalf("%+v", env)
	}
	unchanged, err := WithLogin([]byte("sk_live_plain"), "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != "sk_live_plain" {
		t.Fatalf("%q", unchanged)
	}
}

func TestPackRoundTrip(t *testing.T) {
	raw, err := Pack([]byte("sk_live"), []byte(seed))
	if err != nil {
		t.Fatal(err)
	}
	env := Unpack(raw)
	if env.V != 1 || env.Token != "sk_live" || env.TOTP != seed {
		t.Fatalf("%+v", env)
	}
}

func TestMintMatchesPquerna(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	got, err := Mint(seed, now)
	if err != nil {
		t.Fatal(err)
	}
	want, err := totp.GenerateCode(seed, now)
	if err != nil {
		t.Fatal(err)
	}
	if got != want || len(got) != 6 {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestApplySetsBearerAndTOTP(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	h := http.Header{}
	code, err := Apply(h, Envelope{Token: "sk_live", TOTP: seed}, now)
	if err != nil {
		t.Fatal(err)
	}
	want, err := totp.GenerateCode(seed, now)
	if err != nil {
		t.Fatal(err)
	}
	if h.Get("Authorization") != "Bearer sk_live" {
		t.Fatalf("auth=%q", h.Get("Authorization"))
	}
	if h.Get(HeaderTOTP) != want || code != want {
		t.Fatalf("code=%q header=%q want %q", code, h.Get(HeaderTOTP), want)
	}
}

func TestAuthorizationValue(t *testing.T) {
	if got := AuthorizationValue("sk_live"); got != "Bearer sk_live" {
		t.Fatalf("stripe %q", got)
	}
	if got := AuthorizationValue("lin_api_abc"); got != "lin_api_abc" {
		t.Fatalf("linear %q", got)
	}
	if got := AuthorizationValue("Bearer already"); got != "Bearer already" {
		t.Fatalf("passthrough %q", got)
	}
}
