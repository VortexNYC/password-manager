package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vortexnyc/password-manager/internal/id"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/store"
)

const (
	SessionPrefix     = "ses_"
	sessionSecretLen  = 32
	SessionTTLDefault = 15 * time.Minute
	SessionTTLMax     = time.Hour
)

var (
	ErrForbidden      = errors.New("app: forbidden")
	ErrSessionExpired = errors.New("app: session expired")
)

func IsSessionToken(raw string) bool {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, SessionPrefix) {
		return false
	}
	rest := strings.TrimPrefix(raw, SessionPrefix)
	if len(rest) != sessionSecretLen*2 {
		return false
	}
	_, err := hex.DecodeString(rest)
	return err == nil
}

func sessionHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func newSessionToken() (string, error) {
	var b [sessionSecretLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return SessionPrefix + hex.EncodeToString(b[:]), nil
}

func (a *App) PrincipalFromSession(rawToken string) (protocol.Principal, error) {
	raw := strings.TrimSpace(rawToken)
	if !IsSessionToken(raw) {
		return protocol.Principal{}, fmt.Errorf("app: not a session")
	}
	sess, err := a.Store.SessionByHash(sessionHash(raw))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.Principal{}, fmt.Errorf("app: unauthorized")
		}
		return protocol.Principal{}, err
	}
	if !sess.ExpiresAt.After(time.Now()) {
		return protocol.Principal{}, ErrSessionExpired
	}
	return a.Store.Agent(sess.AgentID)
}

func (a *App) CreateSession(actor protocol.Principal, agentID string, ttl time.Duration) (protocol.Session, string, error) {
	ok, err := a.ownsVault(actor)
	if err != nil {
		return protocol.Session{}, "", err
	}
	if !ok {
		return protocol.Session{}, "", ErrForbidden
	}
	if ttl <= 0 {
		ttl = SessionTTLDefault
	}
	if ttl > SessionTTLMax {
		return protocol.Session{}, "", fmt.Errorf("app: ttl exceeds 1h")
	}
	agent, err := a.Store.Agent(agentID)
	if err != nil {
		return protocol.Session{}, "", err
	}
	token, err := newSessionToken()
	if err != nil {
		return protocol.Session{}, "", err
	}
	sid, err := id.NewSession()
	if err != nil {
		return protocol.Session{}, "", err
	}
	sess := protocol.Session{
		ID:        sid,
		OrgID:     a.OrgID,
		AgentID:   agent.ID,
		ExpiresAt: time.Now().Add(ttl).UTC(),
	}
	if err := a.Store.PutSession(sess, sessionHash(token)); err != nil {
		return protocol.Session{}, "", err
	}
	return sess, token, nil
}

func (a *App) ListSessions(actor protocol.Principal) ([]protocol.Session, error) {
	ok, err := a.ownsVault(actor)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrForbidden
	}
	all, err := a.Store.ListSessions()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]protocol.Session, 0, len(all))
	for _, sess := range all {
		if sess.ExpiresAt.After(now) {
			out = append(out, sess)
		}
	}
	return out, nil
}
