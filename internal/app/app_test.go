package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vortexnyc/password-manager/internal/broker"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/scrub"
)

const secret = "sk_live_APP_TEST_SECRET"

func TestInitUseApprovePersists(t *testing.T) {
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"echo":"`+r.Header.Get("Authorization")+`"}`)
	}))
	t.Cleanup(upstream.Close)

	if _, err := a.AddItem("stripe", upstream.URL, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddAgent("claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddGrant("claude", "stripe", protocol.Level1); err != nil {
		t.Fatal(err)
	}

	got, err := a.Use(context.Background(), "claude", "stripe", http.MethodGet, upstream.URL+"/v1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionNeedApproval {
		t.Fatalf("%+v", got)
	}
	if err := broker.AssertNoSecret(got, []byte(secret)); err != nil {
		t.Fatal(err)
	}

	if _, err := a.Approve("claude:stripe", time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err = a.Use(context.Background(), "claude", "stripe", http.MethodGet, upstream.URL+"/v1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionAllow {
		t.Fatalf("%+v", got)
	}
	if scrub.Contains(got.Fetch.Body, []byte(secret)) {
		t.Fatalf("leak in body: %s", got.Fetch.Body)
	}

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(raw, []byte(secret)) {
		t.Fatal("plaintext in db after close")
	}

	a2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Close()
	items, err := a2.ItemsForAgent("claude")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Name != "stripe" {
		t.Fatalf("%+v", items)
	}
	b, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	if scrub.Contains(b, []byte(secret)) {
		t.Fatal("list leaked secret")
	}

	if _, err := Init(dir); err != ErrExists {
		t.Fatalf("second init: %v", err)
	}
}

func TestLevel2SkipsApproval(t *testing.T) {
	dir := t.TempDir()
	a, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	t.Cleanup(upstream.Close)
	if _, err := a.AddItem("stripe", upstream.URL, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddAgent("ci"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddGrant("ci", "stripe", protocol.Level2); err != nil {
		t.Fatal(err)
	}
	got, err := a.Use(context.Background(), "ci", "stripe", http.MethodGet, upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != protocol.DecisionAllow {
		t.Fatalf("%+v", got)
	}
}
