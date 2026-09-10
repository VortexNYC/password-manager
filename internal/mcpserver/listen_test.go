package mcpserver

import "testing"

func TestListenAddrRailwayPORT(t *testing.T) {
	t.Setenv("PORT", "4461")
	got := ListenAddr(DefaultAddr, false)
	if got != "0.0.0.0:4461" {
		t.Fatalf("got %q", got)
	}
}

func TestListenAddrExplicitWins(t *testing.T) {
	t.Setenv("PORT", "8080")
	got := ListenAddr("127.0.0.1:9999", true)
	if got != "127.0.0.1:9999" {
		t.Fatalf("got %q", got)
	}
}

func TestListenAddrLocalDefault(t *testing.T) {
	t.Setenv("PORT", "")
	got := ListenAddr(DefaultAddr, false)
	if got != DefaultAddr {
		t.Fatalf("got %q", got)
	}
}
