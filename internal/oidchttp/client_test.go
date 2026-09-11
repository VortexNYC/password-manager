package oidchttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransportSetsUserAgent(t *testing.T) {
	var got string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.UserAgent()
		w.WriteHeader(204)
	}))
	t.Cleanup(s.Close)
	c := &http.Client{Transport: transport{}}
	res, err := c.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got != ua {
		t.Fatalf("ua %q", got)
	}
}
