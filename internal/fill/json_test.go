package fill

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/publicapi"
	"github.com/vortexnyc/password-manager/internal/scrub"
)

func jsonHandle(t *testing.T, h *Host, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return h.Handle(raw)
}

func TestJSONProtocolAgainstFakeOrigin(t *testing.T) {
	const login = "stripe@example.com"
	const secretB = secret + "-work"
	const seed = "JBSWY3DPEHPK3PXP"
	a, err := app.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	srv := originAPI(t, a)
	code, raw := originJSON(t, srv, http.MethodPost, "/v1/items", "human", publicapi.CreateItemRequest{
		Name: "stripe-a", URI: "https://dashboard.stripe.com", Secret: secret, Login: login, TOTPSeed: seed,
	})
	if code != http.StatusOK {
		t.Fatalf("a %d %s", code, raw)
	}
	code, raw = originJSON(t, srv, http.MethodPost, "/v1/items", "human", publicapi.CreateItemRequest{
		Name: "stripe-b", URI: "https://dashboard.stripe.com", Secret: secretB, Login: "work@example.com",
	})
	if code != http.StatusOK {
		t.Fatalf("b %d %s", code, raw)
	}
	code, raw = originJSON(t, srv, http.MethodPost, "/v1/items", "human", publicapi.CreateItemRequest{
		Name: "github", URI: "https://github.com", Secret: secret + "-gh",
	})
	if code != http.StatusOK {
		t.Fatalf("github %d %s", code, raw)
	}

	var gets, fills atomic.Int32
	inner := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/items" {
			gets.Add(1)
		}
		if r.Method == http.MethodPost && r.URL.Path == "/v1/fill/logins" {
			fills.Add(1)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			var in publicapi.FillLoginsRequest
			if json.Unmarshal(body, &in) != nil || strings.TrimSpace(in.UUID) == "" {
				t.Errorf("json fill must POST uuid, got %s", body)
			}
		}
		inner.ServeHTTP(w, r)
	})

	h := NewOrigin(t.TempDir(), srv.URL, "human")
	nConfirm := 0
	h.Confirm = func(string) error { nConfirm++; return nil }

	ping := jsonHandle(t, h, map[string]string{"action": "ping"})
	var pong struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(ping, &pong); err != nil || pong.Version != JSONVersion {
		t.Fatalf("ping %s", ping)
	}
	if gets.Load() != 1 {
		t.Fatalf("ping GET /v1/items %d", gets.Load())
	}

	matchRaw := jsonHandle(t, h, map[string]string{"action": "match", "url": "https://dashboard.stripe.com/login"})
	if scrub.Contains(matchRaw, []byte(secret)) || scrub.Contains(matchRaw, []byte(secretB)) || scrub.Contains(matchRaw, []byte(seed)) {
		t.Fatalf("match leaked secret: %s", matchRaw)
	}
	var matched struct {
		Entries []jsonMatchEntry `json:"entries"`
	}
	if err := json.Unmarshal(matchRaw, &matched); err != nil {
		t.Fatal(err)
	}
	if len(matched.Entries) != 2 {
		t.Fatalf("match %+v", matched)
	}
	byUUID := map[string]jsonMatchEntry{}
	for _, e := range matched.Entries {
		byUUID[e.UUID] = e
		if e.Kind != "login" || e.Affiliated {
			t.Fatalf("entry %+v", e)
		}
	}
	if byUUID["stripe-a"].Login != login || !byUUID["stripe-a"].HasTOTP || byUUID["stripe-a"].SavedFor != "dashboard.stripe.com" {
		t.Fatalf("stripe-a %+v", byUUID["stripe-a"])
	}
	if jsonHandle(t, h, map[string]string{"action": "match", "url": "https://dashboard.stripe.com/login"}); gets.Load() != 1 {
		t.Fatalf("match hit origin again GET=%d", gets.Load())
	}

	miss := jsonHandle(t, h, map[string]string{"action": "match", "url": "https://evil.example/login"})
	var empty struct {
		Entries []jsonMatchEntry `json:"entries"`
	}
	if err := json.Unmarshal(miss, &empty); err != nil || len(empty.Entries) != 0 {
		t.Fatalf("wrong host %s", miss)
	}

	ambiguous := jsonHandle(t, h, map[string]string{"action": "fill", "url": "https://dashboard.stripe.com/login"})
	var none struct {
		Entries []jsonFillEntry `json:"entries"`
	}
	if err := json.Unmarshal(ambiguous, &none); err != nil || len(none.Entries) != 0 {
		t.Fatalf("ambiguous fill %+v", none)
	}
	if fills.Load() != 0 || nConfirm != 0 {
		t.Fatalf("ambiguous decrypted fills=%d confirm=%d", fills.Load(), nConfirm)
	}

	one := jsonHandle(t, h, map[string]string{"action": "fill", "url": "https://dashboard.stripe.com/login", "uuid": "stripe-a"})
	if scrub.Contains(one, []byte(secretB)) || scrub.Contains(one, []byte(seed)) {
		t.Fatalf("uuid fill leaked the other secret: %s", one)
	}
	var filled struct {
		Entries []jsonFillEntry `json:"entries"`
	}
	if err := json.Unmarshal(one, &filled); err != nil {
		t.Fatal(err)
	}
	if len(filled.Entries) != 1 || filled.Entries[0].UUID != "stripe-a" || filled.Entries[0].Login != login || filled.Entries[0].Password != secret {
		t.Fatalf("fill %+v", filled)
	}
	if filled.Entries[0].Kind != "login" || len(filled.Entries[0].TOTP) != 6 {
		t.Fatalf("mint totp %+v", filled.Entries[0])
	}
	if fills.Load() != 1 || nConfirm != 1 {
		t.Fatalf("fill origin=%d confirm=%d", fills.Load(), nConfirm)
	}

	again := jsonHandle(t, h, map[string]string{"action": "fill", "url": "https://dashboard.stripe.com/login", "uuid": "stripe-a"})
	if err := json.Unmarshal(again, &filled); err != nil || len(filled.Entries) != 1 || filled.Entries[0].Password != secret {
		t.Fatalf("reuse fill %s", again)
	}
	if nConfirm != 1 {
		t.Fatalf("30s reuse confirmed %d times", nConfirm)
	}

	cross := jsonHandle(t, h, map[string]string{"action": "fill", "url": "https://github.com/login", "uuid": "stripe-a"})
	if err := json.Unmarshal(cross, &none); err != nil || len(none.Entries) != 0 {
		t.Fatalf("cross-host fill %s", cross)
	}

	gen := jsonHandle(t, h, map[string]string{"action": "generate", "url": "https://dashboard.stripe.com"})
	if !bytes.Contains(gen, []byte(`"entries"`)) || scrub.Contains(gen, []byte(secret)) {
		t.Fatalf("generate %s", gen)
	}
}

func TestJSONFillConfirmDeniedDoesNotCallOrigin(t *testing.T) {
	a, err := app.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	srv := originAPI(t, a)
	code, raw := originJSON(t, srv, http.MethodPost, "/v1/items", "human", publicapi.CreateItemRequest{
		Name: "stripe", URI: "https://dashboard.stripe.com", Secret: secret, Login: "a@example.com",
	})
	if code != http.StatusOK {
		t.Fatalf("create %d %s", code, raw)
	}
	var fills atomic.Int32
	inner := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/fill/logins" {
			fills.Add(1)
		}
		inner.ServeHTTP(w, r)
	})
	h := NewOrigin(t.TempDir(), srv.URL, "human")
	h.Confirm = func(string) error { return errors.New("denied") }
	got := jsonHandle(t, h, map[string]string{"action": "fill", "url": "https://dashboard.stripe.com/login", "uuid": "stripe"})
	if scrub.Contains(got, []byte(secret)) {
		t.Fatal("password left after cancel")
	}
	var out struct {
		Entries []jsonFillEntry `json:"entries"`
	}
	if err := json.Unmarshal(got, &out); err != nil || len(out.Entries) != 0 {
		t.Fatalf("%s", got)
	}
	if fills.Load() != 0 {
		t.Fatalf("origin fill after cancel %d", fills.Load())
	}
}

func TestJSONFillUnambiguousUUIDOmitted(t *testing.T) {
	a, err := app.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	srv := originAPI(t, a)
	code, raw := originJSON(t, srv, http.MethodPost, "/v1/items", "human", publicapi.CreateItemRequest{
		Name: "github", URI: "https://github.com", Secret: secret, Login: "ada",
	})
	if code != http.StatusOK {
		t.Fatalf("create %d %s", code, raw)
	}
	h := NewOrigin(t.TempDir(), srv.URL, "human")
	got := jsonHandle(t, h, map[string]string{"action": "fill", "url": "https://github.com/login"})
	var out struct {
		Entries []jsonFillEntry `json:"entries"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 1 || out.Entries[0].UUID != "github" || out.Entries[0].Password != secret || out.Entries[0].Login != "ada" {
		t.Fatalf("%+v", out)
	}
}

func TestJSONNeedLoginOnDeadJWT(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	h := NewOrigin(t.TempDir(), srv.URL, "stale")
	ping := jsonHandle(t, h, map[string]string{"action": "ping"})
	var pong struct {
		Version string `json:"version"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(ping, &pong); err != nil {
		t.Fatal(err)
	}
	if pong.Version != JSONVersion || pong.Error != "need_login" {
		t.Fatalf("ping %s", ping)
	}
	got := jsonHandle(t, h, map[string]string{"action": "fill", "url": "https://example.com/login"})
	var out struct {
		Error   string          `json:"error"`
		Entries []jsonFillEntry `json:"entries"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatal(err)
	}
	if out.Error != "need_login" || len(out.Entries) != 0 {
		t.Fatalf("fill %s", got)
	}
}
