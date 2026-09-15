package otelsetup

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerSkipsHealth(t *testing.T) {
	h := Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health=%d", rec.Code)
	}
}
