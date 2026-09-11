package main

import "testing"

func TestListenAddrUsesPORTOnRailway(t *testing.T) {
	t.Setenv("GLUE_LISTEN", "")
	t.Setenv("PORT", "4456")
	got := listenAddr()
	if got != ":4456" {
		t.Fatalf("got %q", got)
	}
}

func TestListenAddrPrefersExplicit(t *testing.T) {
	t.Setenv("GLUE_LISTEN", "127.0.0.1:4456")
	t.Setenv("PORT", "8080")
	got := listenAddr()
	if got != "127.0.0.1:4456" {
		t.Fatalf("got %q", got)
	}
}

func TestListenAddrLocalDefault(t *testing.T) {
	t.Setenv("GLUE_LISTEN", "")
	t.Setenv("PORT", "")
	got := listenAddr()
	if got != "127.0.0.1:4456" {
		t.Fatalf("got %q", got)
	}
}
