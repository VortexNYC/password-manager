package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vortexnyc/password-manager/identity/glue"
	"github.com/vortexnyc/password-manager/internal/human"
)

func originHumanToken() (string, error) {
	if f := strings.TrimSpace(os.Getenv("PWM_HUMAN_TOKEN_FILE")); f != "" {
		b, err := readFileMaterial(f)
		if err != nil {
			return "", err
		}
		if len(b) == 0 {
			return "", fmt.Errorf("origin: empty PWM_HUMAN_TOKEN_FILE")
		}
		return string(b), nil
	}
	if t := strings.TrimSpace(os.Getenv("PWM_HUMAN_TOKEN")); t != "" {
		return t, nil
	}
	return "", fmt.Errorf("origin: PWM_HUMAN_TOKEN_FILE or PWM_HUMAN_TOKEN is required")
}

func originOwnerToken(ctx context.Context) (string, error) {
	tok, err := originHumanToken()
	if err == nil {
		return tok, nil
	}
	return originTokenLive(ctx, "")
}

func humanLogin(cmd *cobra.Command, outFile string, visit func(string) error) error {
	if outFile == "" {
		return fmt.Errorf("human login: --out-file is required")
	}
	iss := envOr("PWM_HYDRA_ISSUER", "https://id.veil.nyc")
	v, err := human.New(human.Config{
		Issuer:      iss,
		Audience:    envOr("PWM_HYDRA_CLIENT_ID", glue.DefaultClientID),
		RedirectURL: envOr("PWM_HYDRA_REDIRECT", human.DefaultRedirect),
	})
	if err != nil {
		return err
	}
	verifier, state, err := human.PKCE()
	if err != nil {
		return err
	}
	authURL, err := v.AuthCodeURL(cmd.Context(), state, verifier)
	if err != nil {
		return err
	}
	u, err := url.Parse(v.Redirect())
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", u.Host)
	if err != nil {
		return err
	}
	defer ln.Close()
	got := make(chan string, 1)
	errc := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		if e := r.URL.Query().Get("error"); e != "" {
			http.Error(w, e, http.StatusBadRequest)
			errc <- fmt.Errorf("human login: %s", e)
			return
		}
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state", http.StatusBadRequest)
			errc <- fmt.Errorf("human login: state")
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			errc <- fmt.Errorf("human login: missing code")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
		got <- code
	})
	srv := &http.Server{Handler: mux}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	go func() { _ = srv.Serve(ln) }()
	fmt.Fprintln(cmd.ErrOrStderr(), authURL)
	if visit == nil {
		visit = openBrowser
	}
	if err := visit(authURL); err != nil {
		return err
	}
	var code string
	select {
	case <-cmd.Context().Done():
		return cmd.Context().Err()
	case err := <-errc:
		return err
	case code = <-got:
	case <-time.After(10 * time.Minute):
		return fmt.Errorf("human login: timeout")
	}
	raw, err := v.Exchange(cmd.Context(), code, verifier)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outFile, []byte(raw+"\n"), 0o600); err != nil {
		return err
	}
	return encode(cmd, map[string]string{"out_file": outFile})
}

func openBrowser(rawURL string) error {
	if os.Getenv("PWM_LOGIN_NO_OPEN") == "1" {
		return nil
	}
	if runtime.GOOS == "darwin" {
		return exec.Command("open", "-a", "Google Chrome", rawURL).Start()
	}
	return exec.Command("open", rawURL).Start()
}
