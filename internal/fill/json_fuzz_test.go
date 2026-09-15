package fill

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzJSONHandle(f *testing.F) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusNotFound)
	}))
	f.Cleanup(srv.Close)
	f.Add([]byte(`{"action":"ping"}`))
	f.Add([]byte(`{"action":"match","url":"https://github.com/login"}`))
	f.Add([]byte(`{"action":"fill","url":"https://www.amazon.com/checkout","uuid":"amex"}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		h := NewOrigin(t.TempDir(), srv.URL, "human")
		h.Confirm = func(string) error { return errors.New("no") }
		out := h.Handle(raw)
		if !json.Valid(out) {
			t.Fatalf("non-json %q", out)
		}
	})
}
