package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/broker"
	"github.com/vortexnyc/password-manager/internal/crypto"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/publicapi"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dsn := os.Getenv("PG_TEST_DSN")
	if dsn == "" {
		return errors.New("PG_TEST_DSN is required")
	}

	// pgBot and other Postgres tooling expect DATABASE_URL.
	if err := os.Setenv("DATABASE_URL", dsn); err != nil {
		return fmt.Errorf("set DATABASE_URL: %w", err)
	}

	masterKey := os.Getenv("VEIL_MASTER_KEY")
	if masterKey == "" {
		key, err := crypto.NewKey()
		if err != nil {
			return fmt.Errorf("generate master key: %w", err)
		}
		masterKey = hex.EncodeToString(key[:])
		if err := os.Setenv("VEIL_MASTER_KEY", masterKey); err != nil {
			return fmt.Errorf("set VEIL_MASTER_KEY: %w", err)
		}
	}

	a, err := app.OpenPostgres(dsn)
	if err != nil {
		return fmt.Errorf("open origin app: %w", err)
	}
	defer func() { _ = a.Close() }()

	if raw := os.Getenv("VEIL_MAX_IN_FLIGHT_USE"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			a.Broker = broker.NewWithInFlight(a.Store, n)
			a.Broker.Auditor = a.Auditor
		} else if err != nil {
			log.Printf("warning: invalid VEIL_MAX_IN_FLIGHT_USE %q, ignored", raw)
		}
	}

	// Start the upstream server first so we know its URL when creating the item.
	upstreamLn, upstreamURL, err := startUpstream()
	if err != nil {
		return fmt.Errorf("start upstream: %w", err)
	}
	upstreamSrv := &http.Server{Handler: upstreamHandler(), ReadHeaderTimeout: 2 * time.Second}
	defer func() { _ = upstreamSrv.Close() }()
	go func() { _ = upstreamSrv.Serve(upstreamLn) }()

	agentName := envOr("LOADTEST_AGENT", "loadtest-agent")
	itemName := envOr("LOADTEST_ITEM", "loadtest-item")
	secret := []byte(envOr("LOADTEST_SECRET", "sk_live_loadtest_secret"))

	agent, err := a.AddAgent(agentName)
	if err != nil {
		return fmt.Errorf("add agent: %w", err)
	}
	item, err := a.AddItem(itemName, upstreamURL, secret)
	if err != nil {
		return fmt.Errorf("add item: %w", err)
	}
	if _, err := a.AddGrant(agent.ID, item.ID, protocol.Level2); err != nil {
		return fmt.Errorf("add grant: %w", err)
	}

	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: a.HumanID, OrgID: a.OrgID}
	session, token, err := a.CreateSession(human, agent.ID, time.Hour)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	log.Printf("seeded: agent=%s item=%s session=%s", agent.ID, item.ID, session.ID)

	// Start the origin HTTP server.
	originMux := http.NewServeMux()
	srv := &publicapi.Server{App: a}
	srv.Mount(originMux)

	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen origin: %w", err)
	}
	originAddr := originLn.Addr().String()
	originSrv := &http.Server{
		Handler:           originMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	defer func() { _ = originSrv.Close() }()
	go func() { _ = originSrv.Serve(originLn) }()

	originURL := "http://" + originAddr
	log.Printf("origin=%s upstream=%s", originURL, upstreamURL)

	outDir := envOr("LOADTEST_OUT", "tests/load/k6/out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	if err := pgbotInspect(ctx, filepath.Join(outDir, "pgbot-before.json")); err != nil {
		log.Printf("pgbot before: %v", err)
	}

	k6Script := envOr("LOADTEST_K6_SCRIPT", "tests/load/k6/use.js")
	k6Out := filepath.Join(outDir, "k6-summary.json")
	k6Args := []string{"run", "--summary-export", k6Out, k6Script}
	k6Cmd := exec.CommandContext(ctx, "k6", k6Args...)
	k6Cmd.Env = append(os.Environ(),
		"VEIL_ORIGIN="+originURL,
		"VEIL_AGENT_TOKEN="+token,
		"VEIL_ITEM_ID="+item.ID,
		"VEIL_UPSTREAM_URL="+upstreamURL,
	)
	k6Cmd.Stdout = os.Stdout
	k6Cmd.Stderr = os.Stderr
	if err := k6Cmd.Run(); err != nil {
		return fmt.Errorf("k6 run: %w", err)
	}

	if err := pgbotInspect(ctx, filepath.Join(outDir, "pgbot-after.json")); err != nil {
		log.Printf("pgbot after: %v", err)
	}

	log.Printf("load test complete. summary=%s", k6Out)
	return nil
}

func startUpstream() (net.Listener, string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	return ln, "http://" + ln.Addr().String() + "/ok", nil
}

func upstreamHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
}

func pgbotInspect(ctx context.Context, path string) error {
	cmd := exec.CommandContext(ctx, "pgbot", "inspect", "--format", "json")
	out, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create pgbot output file: %w", err)
	}
	defer func() { _ = out.Close() }()
	cmd.Stdout = out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pgbot inspect: %w", err)
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
