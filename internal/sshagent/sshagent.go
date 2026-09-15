// Package sshagent is the OpenSSH agent. It uses golang.org/x/crypto/ssh/agent.
// The broker signs. The private key never leaves the vault.
package sshagent

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/material"
	"github.com/vortexnyc/password-manager/internal/protocol"
)

const Name = "ssh.sock"

var errReadOnly = fmt.Errorf("sshagent: keys live in the vault")

type Server struct {
	Path string
	ln   net.Listener
}

func DefaultPath(home string) string {
	return filepath.Join(home, Name)
}

func Listen(a *app.App, path string) (*Server, error) {
	if path == "" {
		path = DefaultPath(a.Dir)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := removeStale(path); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, err
	}
	s := &Server{Path: path, ln: ln}
	go s.serve(a)
	return s, nil
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	err := s.ln.Close()
	if s.Path != "" {
		_ = os.Remove(s.Path)
	}
	return err
}

func (s *Server) serve(a *app.App) {
	v := &vault{app: a}
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			_ = agent.ServeAgent(v, c)
			_ = c.Close()
		}(c)
	}
}

type vault struct {
	app *app.App
}

func (v *vault) List() ([]*agent.Key, error) {
	signers, err := v.Signers()
	if err != nil {
		return nil, err
	}
	out := make([]*agent.Key, 0, len(signers))
	for _, s := range signers {
		pub := s.PublicKey()
		out = append(out, &agent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: comment(s),
		})
	}
	return out, nil
}

func comment(s ssh.Signer) string {
	if w, ok := s.(*namedSigner); ok {
		return w.name
	}
	return ""
}

func (v *vault) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	signers, err := v.Signers()
	if err != nil {
		return nil, err
	}
	want := string(key.Marshal())
	for _, s := range signers {
		if string(s.PublicKey().Marshal()) == want {
			return s.Sign(nil, data)
		}
	}
	return nil, fmt.Errorf("sshagent: key not in vault")
}

func (v *vault) Add(agent.AddedKey) error   { return errReadOnly }
func (v *vault) Remove(ssh.PublicKey) error { return errReadOnly }
func (v *vault) RemoveAll() error           { return errReadOnly }
func (v *vault) Lock([]byte) error          { return errReadOnly }
func (v *vault) Unlock([]byte) error        { return errReadOnly }

func (v *vault) Signers() ([]ssh.Signer, error) {
	items, err := v.app.Store.ListItems()
	if err != nil {
		return nil, err
	}
	var out []ssh.Signer
	for _, item := range items {
		if item.Kind != protocol.ItemSSH {
			continue
		}
		s, err := signerFor(v.app, item)
		if err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

type namedSigner struct {
	ssh.Signer
	name string
}

func signerFor(a *app.App, item protocol.Item) (ssh.Signer, error) {
	sec, err := a.Store.Secret(item.ID)
	if err != nil {
		return nil, err
	}
	raw := pemBytes(sec)
	s, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, err
	}
	return &namedSigner{Signer: s, name: item.Name}, nil
}

func pemBytes(sec []byte) []byte {
	env := material.Unpack(sec)
	if strings.Contains(env.Token, "PRIVATE KEY") {
		return []byte(env.Token)
	}
	return sec
}

func removeStale(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("sshagent: %s exists and is not a socket", path)
	}
	return os.Remove(path)
}
