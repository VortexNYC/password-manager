package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/veilnyc/password-manager/internal/app"
	"github.com/veilnyc/password-manager/internal/broker"
	"github.com/veilnyc/password-manager/internal/crypto"
	"github.com/veilnyc/password-manager/internal/protocol"
	"github.com/veilnyc/password-manager/internal/publicapi"
)

type origin struct {
	app *app.App
	srv *http.Server
	ln  net.Listener
	url string
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel(),
	})))
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func logLevel() slog.Leveler {
	switch strings.ToLower(os.Getenv("VEIL_LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelWarn
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	useProxy := envOr("LOADTEST_PROXY", "1") != "0"

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

	replicas := envOrInt("LOADTEST_REPLICAS", 1)
	if replicas < 1 {
		replicas = 1
	}

	// Start the upstream server first so we know its URL when creating the item.
	upstreamLn, upstreamURL, err := startUpstream()
	if err != nil {
		return fmt.Errorf("start upstream: %w", err)
	}
	upstreamSrv := &http.Server{Handler: upstreamHandler(), ReadHeaderTimeout: 2 * time.Second}
	defer func() { _ = upstreamSrv.Close() }()
	go func() { _ = upstreamSrv.Serve(upstreamLn) }()

	// Start N stateless origin replicas. Each has its own Store pool and auditor
	// worker, just like separate Railway containers behind a load balancer.
	origins, err := startOrigins(dsn, masterKey, replicas)
	if err != nil {
		return err
	}
	defer closeOrigins(origins)

	agent, item, session, token, err := seed(origins[0].app, upstreamURL)
	if err != nil {
		return err
	}

	var k6Origins []string
	var proxyURL string
	if useProxy {
		var proxySrv *http.Server
		var proxyLn net.Listener
		proxyURL, proxySrv, proxyLn, err = startProxy(origins)
		if err != nil {
			return fmt.Errorf("start proxy: %w", err)
		}
		defer func() { _ = proxySrv.Close() }()
		go func() { _ = proxySrv.Serve(proxyLn) }()
		k6Origins = []string{proxyURL}
		log.Printf("origin replicas=%d proxy=%s upstream=%s", len(origins), proxyURL, upstreamURL)
	} else {
		proxyURL = origins[0].url
		k6Origins = make([]string, len(origins))
		for i, o := range origins {
			k6Origins[i] = o.url
		}
		log.Printf("origin replicas=%d direct upstream=%s", len(origins), upstreamURL)
	}

	outDir := envOr("LOADTEST_OUT", "tests/load/k6/out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	if err := resetPGSS(ctx, dsn); err != nil {
		log.Printf("pg_stat_statements reset: %v", err)
	}

	if err := pgbotInspect(ctx, filepath.Join(outDir, "pgbot-before.json")); err != nil {
		log.Printf("pgbot before: %v", err)
	}

	cpuPath := filepath.Join(outDir, "cpu.pprof")
	cpuF, err := os.Create(cpuPath)
	if err != nil {
		return fmt.Errorf("create cpu profile: %w", err)
	}
	if err := pprof.StartCPUProfile(cpuF); err != nil {
		_ = cpuF.Close()
		return fmt.Errorf("start cpu profile: %w", err)
	}

	k6Script := envOr("LOADTEST_K6_SCRIPT", "tests/load/k6/use.js")
	k6Out := filepath.Join(outDir, "k6-summary.json")
	k6Args := []string{"run", "--summary-export", k6Out, k6Script}
	k6Cmd := exec.CommandContext(ctx, "k6", k6Args...)
	k6Cmd.Env = append(os.Environ(),
		"VEIL_ORIGINS="+strings.Join(k6Origins, ","),
		"VEIL_ORIGIN="+proxyURL,
		"VEIL_AGENT_TOKEN="+token,
		"VEIL_ITEM_ID="+item.ID,
		"VEIL_UPSTREAM_URL="+upstreamURL,
	)
	k6Cmd.Stdout = os.Stdout
	k6Cmd.Stderr = os.Stderr
	if err := k6Cmd.Run(); err != nil {
		pprof.StopCPUProfile()
		_ = cpuF.Close()
		return fmt.Errorf("k6 run: %w", err)
	}

	pprof.StopCPUProfile()
	_ = cpuF.Close()

	heapPath := filepath.Join(outDir, "heap.pprof")
	heapF, err := os.Create(heapPath)
	if err != nil {
		return fmt.Errorf("create heap profile: %w", err)
	}
	if err := pprof.WriteHeapProfile(heapF); err != nil {
		_ = heapF.Close()
		return fmt.Errorf("write heap profile: %w", err)
	}
	_ = heapF.Close()

	// Stop origins and flush any pending audit batches before taking the final
	// pgbot snapshot, so pg_stat_statements reflects the complete workload.
	closeOrigins(origins)

	if err := pgbotInspect(ctx, filepath.Join(outDir, "pgbot-after.json")); err != nil {
		log.Printf("pgbot after: %v", err)
	}

	log.Printf("load test complete. replicas=%d summary=%s", len(origins), k6Out)

	_ = agent
	_ = session
	return nil
}

func startOrigins(dsn, masterKey string, n int) ([]*origin, error) {
	maxInFlight := 0
	if raw := os.Getenv("VEIL_MAX_IN_FLIGHT_USE"); raw != "" {
		if m, err := strconv.Atoi(raw); err == nil && m > 0 {
			maxInFlight = m
		} else if err != nil {
			log.Printf("warning: invalid VEIL_MAX_IN_FLIGHT_USE %q, ignored", raw)
		}
	}

	origins := make([]*origin, n)
	for i := 0; i < n; i++ {
		a, err := app.OpenPostgres(dsn)
		if err != nil {
			closeOrigins(origins[:i])
			return nil, fmt.Errorf("open origin %d: %w", i, err)
		}
		if maxInFlight > 0 {
			a.Broker = broker.NewWithInFlight(a.Store, maxInFlight)
			a.Broker.Auditor = a.Auditor
		}

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			_ = a.Close()
			closeOrigins(origins[:i])
			return nil, fmt.Errorf("listen origin %d: %w", i, err)
		}

		mux := http.NewServeMux()
		srv := &publicapi.Server{App: a}
		srv.Mount(mux)
		originSrv := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
		origins[i] = &origin{app: a, srv: originSrv, ln: ln, url: "http://" + ln.Addr().String()}
		go func(s *http.Server, l net.Listener) { _ = s.Serve(l) }(originSrv, ln)
	}
	return origins, nil
}

func closeOrigins(origins []*origin) {
	var wg sync.WaitGroup
	for _, o := range origins {
		if o == nil || o.app == nil {
			continue
		}
		wg.Add(1)
		go func(o *origin) {
			defer wg.Done()
			_ = o.srv.Close()
			_ = o.app.Close()
			o.srv = nil
			o.app = nil
		}(o)
	}
	wg.Wait()
}

func seed(a *app.App, upstreamURL string) (protocol.Principal, protocol.Item, protocol.Session, string, error) {
	agentName := envOr("LOADTEST_AGENT", "loadtest-agent")
	itemName := envOr("LOADTEST_ITEM", "loadtest-item")
	secret := []byte(envOr("LOADTEST_SECRET", "sk_live_loadtest_secret"))

	agent, err := a.AddAgent(agentName)
	if err != nil {
		return protocol.Principal{}, protocol.Item{}, protocol.Session{}, "", fmt.Errorf("add agent: %w", err)
	}
	item, err := a.AddItem(itemName, upstreamURL, secret)
	if err != nil {
		return protocol.Principal{}, protocol.Item{}, protocol.Session{}, "", fmt.Errorf("add item: %w", err)
	}
	if _, err := a.AddGrant(agent.ID, item.ID, protocol.Level2); err != nil {
		return protocol.Principal{}, protocol.Item{}, protocol.Session{}, "", fmt.Errorf("add grant: %w", err)
	}
	human := protocol.Principal{Kind: protocol.PrincipalHuman, ID: a.HumanID, OrgID: a.OrgID}
	session, token, err := a.CreateSession(human, agent.ID, time.Hour, 0)
	if err != nil {
		return protocol.Principal{}, protocol.Item{}, protocol.Session{}, "", fmt.Errorf("create session: %w", err)
	}
	log.Printf("seeded: agent=%s item=%s session=%s", agent.ID, item.ID, session.ID)
	return agent, item, session, token, nil
}

func startProxy(origins []*origin) (string, *http.Server, net.Listener, error) {
	urls := make([]*url.URL, len(origins))
	for i, o := range origins {
		u, err := url.Parse(o.url)
		if err != nil {
			return "", nil, nil, fmt.Errorf("parse origin url %q: %w", o.url, err)
		}
		urls[i] = u
	}

	var counter uint64
	proxy := httputil.NewSingleHostReverseProxy(urls[0])
	proxy.Director = nil
	proxy.Rewrite = func(pr *httputil.ProxyRequest) {
		idx := atomic.AddUint64(&counter, 1) % uint64(len(urls))
		pr.SetURL(urls[idx])
		pr.Out.Host = urls[idx].Host
	}
	// The default transport only keeps two idle connections per host, which
	// causes connection churn and port exhaustion under high request rates.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 100
	proxy.Transport = transport

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, nil, fmt.Errorf("listen proxy: %w", err)
	}
	srv := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	return "http://" + ln.Addr().String(), srv, ln, nil
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
	cmd := exec.CommandContext(ctx, "pgbot", "inspect", "--format", "json", "--fail-on", "none")
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

func resetPGSS(ctx context.Context, dsn string) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect to reset pg_stat_statements: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "SELECT pg_stat_statements_reset()"); err != nil {
		return fmt.Errorf("pg_stat_statements_reset: %w", err)
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("warning: invalid %s %q, using fallback %d", key, raw, fallback)
		return fallback
	}
	return n
}
