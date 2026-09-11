// Package cli is the human surface and the origin HTTP client (PWM_ORIGIN).
// Cobra, stdin for secrets, no `get` that prints material — same shape as MeowPass.
// Production agents use MCP. Dogfood and humans use these commands against origin.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/vortexnyc/password-manager/identity/glue"
	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/device"
	"github.com/vortexnyc/password-manager/internal/fill"
	"github.com/vortexnyc/password-manager/internal/human"
	"github.com/vortexnyc/password-manager/internal/id"
	"github.com/vortexnyc/password-manager/internal/mcpserver"
	"github.com/vortexnyc/password-manager/internal/otelsetup"
	"github.com/vortexnyc/password-manager/internal/passgen"
	"github.com/vortexnyc/password-manager/internal/protocol"
	"github.com/vortexnyc/password-manager/internal/proxy"
	"github.com/vortexnyc/password-manager/internal/socket"
	"github.com/vortexnyc/password-manager/internal/sshagent"
	"github.com/vortexnyc/password-manager/internal/totpenroll"
)

func New(version string) *cobra.Command {
	var home string
	root := &cobra.Command{
		Use:           "password-manager",
		Short:         "Veil. Agents never hold secrets.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	root.PersistentFlags().StringVar(&home, "home", "", "vault directory (env PWM_HOME, default ~/.password-manager)")
	root.SetVersionTemplate("{{.Version}}\n")

	root.AddCommand(initCmd(&home))
	root.AddCommand(deviceCmd(&home))
	root.AddCommand(humanCmd(&home))
	root.AddCommand(itemCmd(&home))
	root.AddCommand(agentCmd(&home))
	root.AddCommand(grantCmd(&home))
	root.AddCommand(useCmd(&home))
	root.AddCommand(approveCmd(&home))
	root.AddCommand(mcpCmd(&home))
	root.AddCommand(proxyCmd(&home))
	root.AddCommand(runCmd(&home))
	root.AddCommand(serveCmd(&home))
	root.AddCommand(fillCmd(&home))
	root.AddCommand(sshCmd(&home))
	root.AddCommand(auditCmd(&home))
	root.AddCommand(genCmd())
	root.AddCommand(totpCmd())
	return root
}

func resolveHome(home string) (string, error) {
	if home != "" {
		return home, nil
	}
	if v := os.Getenv("PWM_HOME"); v != "" {
		return v, nil
	}
	dir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ".password-manager"), nil
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func glueFromEnv() (*glue.Glue, error) {
	return glue.New(glue.Config{
		KratosPublic: envOr("PWM_KRATOS_PUBLIC", "http://127.0.0.1:4433"),
		KratosAdmin:  envOr("PWM_KRATOS_ADMIN", "http://127.0.0.1:4434"),
		HydraAdmin:   envOr("PWM_HYDRA_ADMIN", "http://127.0.0.1:4445"),
		KetoRead:     envOr("PWM_KETO_READ", "http://127.0.0.1:4466"),
		KetoWrite:    envOr("PWM_KETO_WRITE", "http://127.0.0.1:4467"),
		OrgID:        envOr("PWM_ORG_ID", glue.LocalOrgID),
	})
}

func resolveHumanGrantee(ctx context.Context, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("grant add: --human required")
	}
	if !strings.Contains(raw, "@") {
		return raw, nil
	}
	g, err := glueFromEnv()
	if err != nil {
		return "", err
	}
	id, err := g.IdentityID(ctx, raw)
	if err != nil {
		return "", err
	}
	return id, nil
}

func openApp(home string) (*app.App, error) {
	return loadApp(home, false)
}

func openOrInitApp(home string) (*app.App, error) {
	return loadApp(home, true)
}

func loadApp(home string, initEmpty bool) (*app.App, error) {
	if originBase() != "" {
		return nil, fmt.Errorf("PWM_ORIGIN is set; origin is the vault")
	}
	dir, err := resolveHome(home)
	if err != nil {
		return nil, err
	}
	var a *app.App
	if initEmpty {
		a, err = app.OpenOrInit(dir)
	} else {
		a, err = app.Open(dir)
	}
	if err != nil {
		return nil, err
	}
	g, err := glueFromEnv()
	if err != nil {
		_ = a.Close()
		return nil, err
	}
	a.Members = g
	return a, nil
}

func inviteActor(ctx context.Context, tokenFile, orgID string) (string, error) {
	raw, err := humanToken(tokenFile)
	if err != nil {
		return "", err
	}
	if raw == "" {
		return "", nil
	}
	iss := os.Getenv("PWM_HYDRA_ISSUER")
	if iss == "" {
		return "", fmt.Errorf("invite: hydra issuer required to prove owner")
	}
	v, err := human.New(human.Config{
		Issuer:      iss,
		Audience:    os.Getenv("PWM_HYDRA_CLIENT_ID"),
		RedirectURL: envOr("PWM_HYDRA_REDIRECT", "http://127.0.0.1:4460/oidc/callback"),
	})
	if err != nil {
		return "", err
	}
	p, err := v.Human(ctx, raw, orgID)
	if err != nil {
		return "", err
	}
	return p.ID, nil
}

func initCmd(home *string) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create a local vault (org of one)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if originBase() != "" {
				return fmt.Errorf("PWM_ORIGIN is set; origin is the vault")
			}
			dir, err := resolveHome(*home)
			if err != nil {
				return err
			}
			a, err := app.Init(dir)
			if err != nil {
				return err
			}
			defer a.Close()
			fmt.Fprintf(cmd.OutOrStdout(), "initialized %s\n", dir)
			return nil
		},
	}
}

func deviceCmd(home *string) *cobra.Command {
	c := &cobra.Command{Use: "device", Short: "Pair a second machine. Does not pair a model."}
	var keyFile, pubFile, toFile, fromFile string

	newCmd := &cobra.Command{
		Use:   "new",
		Short: "Create a device private key. Never stdout.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyFile == "" {
				return fmt.Errorf("--key-file is required")
			}
			_, priv, err := device.Generate()
			if err != nil {
				return err
			}
			if err := os.WriteFile(keyFile, priv, 0o600); err != nil {
				return err
			}
			return encode(cmd, map[string]bool{"ok": true})
		},
	}
	newCmd.Flags().StringVar(&keyFile, "key-file", "", "write the device private key here. never argv.")
	_ = newCmd.MarkFlagRequired("key-file")

	pubkey := &cobra.Command{
		Use:   "pubkey",
		Short: "Write the box public key. Not a secret.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyFile == "" || pubFile == "" {
				return fmt.Errorf("--key-file and --out-file are required")
			}
			priv, err := os.ReadFile(keyFile)
			if err != nil {
				return err
			}
			pub, err := device.Public(priv)
			if err != nil {
				return err
			}
			if err := os.WriteFile(pubFile, pub, 0o600); err != nil {
				return err
			}
			return encode(cmd, map[string]bool{"ok": true})
		},
	}
	pubkey.Flags().StringVar(&keyFile, "key-file", "", "device private key file")
	pubkey.Flags().StringVar(&pubFile, "out-file", "", "write the public key here")
	_ = pubkey.MarkFlagRequired("key-file")
	_ = pubkey.MarkFlagRequired("out-file")

	offer := &cobra.Command{
		Use:   "offer",
		Short: "Wrap master to a public key. Blob is a file, never JSON.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if pubFile == "" || toFile == "" {
				return fmt.Errorf("--pubkey-file and --to-file are required")
			}
			peer, err := os.ReadFile(pubFile)
			if err != nil {
				return err
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			blob, err := a.Offer(peer)
			if err != nil {
				return err
			}
			if err := os.WriteFile(toFile, blob, 0o600); err != nil {
				return err
			}
			return encode(cmd, map[string]int{"bytes": len(blob)})
		},
	}
	offer.Flags().StringVar(&pubFile, "pubkey-file", "", "the other device's public key")
	offer.Flags().StringVar(&toFile, "to-file", "", "write the wrap here. never stdout.")
	_ = offer.MarkFlagRequired("pubkey-file")
	_ = offer.MarkFlagRequired("to-file")

	accept := &cobra.Command{
		Use:   "accept",
		Short: "Write device.key and a wrap. Copy vault.db yourself.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyFile == "" || fromFile == "" {
				return fmt.Errorf("--key-file and --from-file are required")
			}
			priv, err := os.ReadFile(keyFile)
			if err != nil {
				return err
			}
			blob, err := os.ReadFile(fromFile)
			if err != nil {
				return err
			}
			dir, err := resolveHome(*home)
			if err != nil {
				return err
			}
			if originBase() != "" {
				return fmt.Errorf("PWM_ORIGIN is set; origin is the vault")
			}
			if err := app.Accept(dir, priv, blob); err != nil {
				return err
			}
			return encode(cmd, map[string]bool{"ok": true})
		},
	}
	accept.Flags().StringVar(&keyFile, "key-file", "", "this device's private key")
	accept.Flags().StringVar(&fromFile, "from-file", "", "the wrap from offer")
	_ = accept.MarkFlagRequired("key-file")
	_ = accept.MarkFlagRequired("from-file")

	c.AddCommand(newCmd, pubkey, offer, accept)
	return c
}

func humanCmd(home *string) *cobra.Command {
	c := &cobra.Command{Use: "human", Short: "Humans in this org. Identities live in Kratos."}
	var codeFile, tokenFile string
	invite := &cobra.Command{
		Use:   "invite EMAIL",
		Short: "Kratos identity plus recovery code. Owner-gated after bootstrap. Never argv.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if codeFile == "" {
				return fmt.Errorf("--code-file is required")
			}
			g, err := glueFromEnv()
			if err != nil {
				return err
			}
			actor, err := inviteActor(cmd.Context(), tokenFile, envOr("PWM_ORG_ID", glue.LocalOrgID))
			if err != nil {
				return err
			}
			inv, err := g.InviteIdentity(cmd.Context(), args[0], actor)
			if err != nil {
				return err
			}
			if err := os.WriteFile(codeFile, []byte(inv.Code+"\n"), 0o600); err != nil {
				return err
			}
			return encode(cmd, inviteDTO{IdentityID: inv.IdentityID, RecoveryLink: inv.RecoveryLink})
		},
	}
	invite.Flags().StringVar(&codeFile, "code-file", "", "write the Kratos recovery code here. never argv.")
	invite.Flags().StringVar(&tokenFile, "oidc-token-file", "", "owner Hydra ID token file. Env PWM_HUMAN_TOKEN. Never argv.")
	_ = invite.MarkFlagRequired("code-file")
	var outFile string
	login := &cobra.Command{
		Use:   "login",
		Short: "Mint a Hydra ID token for this human. Writes --out-file. Never stdout.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return humanLogin(cmd, outFile, nil)
		},
	}
	login.Flags().StringVar(&outFile, "out-file", "", "write the ID token here. never stdout.")
	_ = login.MarkFlagRequired("out-file")
	list := &cobra.Command{
		Use:   "list",
		Short: "List humans (Kratos identity ids, no email)",
		RunE: func(cmd *cobra.Command, args []string) error {
			g, err := glueFromEnv()
			if err == nil {
				ids, err := g.ListMembers(cmd.Context())
				if err == nil {
					org := envOr("PWM_ORG_ID", glue.LocalOrgID)
					humans := make([]protocol.Principal, 0, len(ids))
					for _, id := range ids {
						humans = append(humans, protocol.Principal{Kind: protocol.PrincipalHuman, ID: id, OrgID: org})
					}
					return encode(cmd, humans)
				}
			}
			if originBase() != "" {
				if err != nil {
					return err
				}
				return fmt.Errorf("human list: keto")
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			humans, err := a.Store.ListHumans()
			if err != nil {
				return err
			}
			if humans == nil {
				humans = []protocol.Principal{}
			}
			return encode(cmd, humans)
		},
	}
	c.AddCommand(invite, login, list)
	return c
}

type inviteDTO struct {
	IdentityID   string `json:"identity_id"`
	RecoveryLink string `json:"recovery_link,omitempty"`
}

func itemCmd(home *string) *cobra.Command {
	c := &cobra.Command{Use: "item", Short: "Items (metadata only on list)"}
	var uri, secretFile, totpFile, refreshFile, clientSecretFile, tokenURL, clientID, sshFile, attachFile, mime, login string
	var updateURIs []string
	var tags []string
	add := &cobra.Command{
		Use:   "add NAME",
		Short: "Store material from files. Never argv. OAuth refresh stays in the broker.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var token, totpSeed, refresh, clientSecret, fileBody []byte
			var kind protocol.ItemKind
			var err error
			fileName := ""
			if attachFile != "" {
				fileBody, err = os.ReadFile(attachFile)
				if err != nil {
					return err
				}
				fileName = filepath.Base(attachFile)
				kind = protocol.ItemFile
			} else if sshFile != "" {
				if secretFile != "" || refreshFile != "" || totpFile != "" {
					return fmt.Errorf("--ssh-file is the private key. not --secret-file")
				}
				token, err = readFileMaterial(sshFile)
				if err != nil {
					return err
				}
				if _, err := ssh.ParsePrivateKey(token); err != nil {
					return fmt.Errorf("item: not an ssh private key: %w", err)
				}
				kind = protocol.ItemSSH
			} else if refreshFile != "" {
				refresh, err = readFileMaterial(refreshFile)
				if err != nil {
					return err
				}
				if totpFile != "" {
					totpSeed, err = readFileMaterial(totpFile)
					if err != nil {
						return err
					}
				}
			} else {
				token, totpSeed, err = readItemMaterial(secretFile, totpFile, cmd.InOrStdin())
				if err != nil {
					return err
				}
			}
			if clientSecretFile != "" {
				clientSecret, err = readFileMaterial(clientSecretFile)
				if err != nil {
					return err
				}
			}
			if originBase() != "" {
				if attachFile != "" || sshFile != "" || refreshFile != "" {
					return fmt.Errorf("origin: item add is --secret-file/--totp-file")
				}
				return originItemAdd(cmd, args[0], uri, tags, kind, token, totpSeed, login)
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			item, err := a.PutItem(app.ItemOpts{
				Name:         args[0],
				URI:          uri,
				Tags:         tags,
				Kind:         kind,
				Token:        token,
				Login:        login,
				TOTPSeed:     totpSeed,
				Refresh:      refresh,
				TokenURL:     tokenURL,
				ClientID:     clientID,
				ClientSecret: clientSecret,
				FileName:     fileName,
				MIME:         mime,
				File:         fileBody,
			})
			if err != nil {
				return err
			}
			return encode(cmd, item)
		},
	}
	add.Flags().StringVar(&uri, "uri", "", "host this item may be used against, e.g. https://api.stripe.com")
	add.Flags().StringSliceVar(&tags, "tag", nil, "owner label. not ACL")
	add.Flags().StringVar(&login, "login", "", "fill username. sealed. not list. not MCP")
	add.Flags().StringVar(&secretFile, "secret-file", "", "file containing the API key (`-` for stdin)")
	add.Flags().StringVar(&sshFile, "ssh-file", "", "OpenSSH/PEM private key file. Never argv. Kind becomes ssh.")
	add.Flags().StringVar(&totpFile, "totp-file", "", "file containing the TOTP seed, never the 6-digit code")
	add.Flags().StringVar(&refreshFile, "refresh-file", "", "OAuth refresh token file. Never argv.")
	add.Flags().StringVar(&clientSecretFile, "client-secret-file", "", "OAuth client secret file. Never argv.")
	add.Flags().StringVar(&tokenURL, "token-url", "", "OAuth token endpoint")
	add.Flags().StringVar(&clientID, "client-id", "", "OAuth client id")
	add.Flags().StringVar(&attachFile, "file", "", "seal a document. never argv. not MCP.")
	add.Flags().StringVar(&mime, "mime", "", "optional content type for --file")
	list := &cobra.Command{
		Use:   "list",
		Short: "List items (no secrets)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if originBase() != "" {
				return originItemList(cmd)
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			items, err := a.Store.ListItems()
			if err != nil {
				return err
			}
			if items == nil {
				items = []protocol.Item{}
			}
			return encode(cmd, items)
		},
	}
	update := &cobra.Command{
		Use:   "update NAME",
		Short: "Add autofill hosts, replace tags, set login. Snapshots history. No secret on argv.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if originBase() != "" {
				return originItemUpdate(cmd, args[0], updateURIs, tags, login)
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			item, err := a.UpdateItem(args[0], nil, updateURIs, tags, login)
			if err != nil {
				return err
			}
			return encode(cmd, item)
		},
	}
	update.Flags().StringSliceVar(&updateURIs, "uri", nil, "add autofill host. repeatable. does not drop existing")
	update.Flags().StringSliceVar(&tags, "tag", nil, "replace tags")
	update.Flags().StringVar(&login, "login", "", "set fill username. does not rotate the secret")
	archive := &cobra.Command{
		Use:   "archive NAME",
		Short: "Hide from Use and list. History stays.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if originBase() != "" {
				return originItemArchive(cmd, args[0])
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			if err := a.ArchiveItem(args[0]); err != nil {
				return err
			}
			return encode(cmd, map[string]bool{"archived": true})
		},
	}
	del := &cobra.Command{
		Use:   "delete NAME",
		Short: "Remove the item and its grants.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if originBase() != "" {
				return originItemDelete(cmd, args[0])
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			if err := a.DeleteItem(args[0]); err != nil {
				return err
			}
			return encode(cmd, map[string]bool{"deleted": true})
		},
	}
	versions := &cobra.Command{
		Use:   "versions NAME",
		Short: "List sealed history. No secret.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			vs, err := a.Store.Versions(args[0])
			if err != nil {
				return err
			}
			if vs == nil {
				vs = []protocol.ItemVersion{}
			}
			return encode(cmd, vs)
		},
	}
	var versionID int64
	restore := &cobra.Command{
		Use:   "restore NAME",
		Short: "Restore a sealed version. Snapshots current first.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			if err := a.Store.RestoreVersion(args[0], versionID); err != nil {
				return err
			}
			return encode(cmd, map[string]bool{"restored": true})
		},
	}
	restore.Flags().Int64Var(&versionID, "version", 0, "version id from item versions")
	_ = restore.MarkFlagRequired("version")
	var outFile string
	write := &cobra.Command{
		Use:   "write NAME",
		Short: "Owner: write a sealed file to disk. Not MCP.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if outFile == "" {
				return fmt.Errorf("--out-file is required")
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			if err := a.WriteFile(args[0], outFile); err != nil {
				return err
			}
			return encode(cmd, map[string]bool{"ok": true})
		},
	}
	write.Flags().StringVar(&outFile, "out-file", "", "destination path. never stdout.")
	_ = write.MarkFlagRequired("out-file")
	c.AddCommand(add, list, update, archive, del, versions, restore, write)
	return c
}

func agentCmd(home *string) *cobra.Command {
	c := &cobra.Command{Use: "agent", Short: "Agent principals"}
	c.AddCommand(&cobra.Command{
		Use:   "add NAME",
		Short: "Register an agent principal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			p, err := a.AddAgent(args[0])
			if err != nil {
				return err
			}
			return encode(cmd, p)
		},
	})
	c.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List agents",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			agents, err := a.Store.ListAgents()
			if err != nil {
				return err
			}
			if agents == nil {
				agents = []protocol.Principal{}
			}
			return encode(cmd, agents)
		},
	})
	var issuer, subject, audience string
	bind := &cobra.Command{
		Use:   "bind NAME",
		Short: "Bind an existing agent to an external OIDC issuer and subject",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			w, err := a.BindWorkload(args[0], issuer, subject, audience)
			if err != nil {
				return err
			}
			return encode(cmd, w)
		},
	}
	bind.Flags().StringVar(&issuer, "issuer", "", "OIDC issuer URL we verify, not one we run")
	bind.Flags().StringVar(&subject, "subject", "", "token sub claim for this agent")
	bind.Flags().StringVar(&audience, "audience", "", "expected token aud")
	_ = bind.MarkFlagRequired("issuer")
	_ = bind.MarkFlagRequired("subject")
	_ = bind.MarkFlagRequired("audience")
	c.AddCommand(bind)

	var secretFile string
	hydra := &cobra.Command{
		Use:   "hydra NAME",
		Short: "Hydra client for an agent that does not speak OIDC. Not a Kratos human.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if secretFile == "" {
				return fmt.Errorf("--secret-file is required")
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			if _, err := a.Store.Agent(args[0]); err != nil {
				return err
			}
			g, err := glue.NewHydra(envOr("PWM_HYDRA_ADMIN", "http://127.0.0.1:4445"))
			if err != nil {
				return err
			}
			cred, err := g.EnsureAgent(cmd.Context(), glue.AgentClient{
				ID:       glue.AgentClientID(args[0]),
				Audience: envOr("PWM_HYDRA_CLIENT_ID", glue.DefaultClientID),
			})
			if err != nil {
				return err
			}
			if cred.Secret != "" {
				if err := os.WriteFile(secretFile, []byte(cred.Secret+"\n"), 0o600); err != nil {
					return err
				}
			} else if _, err := os.Stat(secretFile); err != nil {
				return fmt.Errorf("agent hydra: client exists; secret is not reissued")
			}
			issuer := envOr("PWM_HYDRA_ISSUER", "http://127.0.0.1:4444")
			w, err := a.BindWorkload(args[0], issuer, cred.ID, cred.Audience)
			if err != nil {
				return err
			}
			return encode(cmd, hydraAgentDTO{
				AgentID:  args[0],
				ClientID: cred.ID,
				Issuer:   w.Issuer,
				Audience: w.Audience,
			})
		},
	}
	hydra.Flags().StringVar(&secretFile, "secret-file", "", "write the Hydra client secret here. never argv.")
	_ = hydra.MarkFlagRequired("secret-file")
	c.AddCommand(hydra)

	var tokenSecretFile, outFile string
	token := &cobra.Command{
		Use:   "token NAME",
		Short: "Mint a Hydra JWT. Writes --out-file. Never prints the token or the secret.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if tokenSecretFile == "" || outFile == "" {
				return fmt.Errorf("--secret-file and --out-file are required")
			}
			if !id.Valid(args[0]) {
				return fmt.Errorf("agent token: invalid name")
			}
			secret, err := readFileMaterial(tokenSecretFile)
			if err != nil {
				return err
			}
			if len(secret) == 0 {
				return fmt.Errorf("agent token: empty secret")
			}
			issuer := envOr("PWM_HYDRA_ISSUER", "http://127.0.0.1:4444")
			audience := envOr("PWM_HYDRA_CLIENT_ID", glue.DefaultClientID)
			clientID := glue.AgentClientID(args[0])
			raw, err := glue.ClientCredentials(cmd.Context(), issuer, clientID, string(secret), audience)
			if err != nil {
				return err
			}
			if err := os.WriteFile(outFile, []byte(raw+"\n"), 0o600); err != nil {
				return err
			}
			return encode(cmd, tokenDTO{
				AgentID:  args[0],
				ClientID: clientID,
				Issuer:   issuer,
				Audience: audience,
				OutFile:  outFile,
			})
		},
	}
	token.Flags().StringVar(&tokenSecretFile, "secret-file", "", "Hydra client secret file. never argv.")
	token.Flags().StringVar(&outFile, "out-file", "", "write the JWT here. never stdout.")
	_ = token.MarkFlagRequired("secret-file")
	_ = token.MarkFlagRequired("out-file")
	c.AddCommand(token)
	return c
}

type tokenDTO struct {
	AgentID  string `json:"agent_id"`
	ClientID string `json:"client_id"`
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	OutFile  string `json:"out_file"`
}

type hydraAgentDTO struct {
	AgentID  string `json:"agent_id"`
	ClientID string `json:"client_id"`
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
}

func grantCmd(home *string) *cobra.Command {
	c := &cobra.Command{Use: "grant", Short: "Per-item grants. Agent or Kratos human. Same object."}
	var agentName, humanName, itemName, level string
	var expires time.Duration
	add := &cobra.Command{
		Use:   "add",
		Short: "Grant Use on an item (level1 or level2). --agent XOR --human.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if (agentName == "") == (humanName == "") {
				return fmt.Errorf("grant add: --agent or --human")
			}
			grantee := agentName
			asHuman := humanName != ""
			if asHuman {
				got, err := resolveHumanGrantee(cmd.Context(), humanName)
				if err != nil {
					return err
				}
				grantee = got
			}
			if originBase() != "" {
				return originGrantAdd(cmd, grantee, itemName, level, expires, asHuman)
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			var until *time.Time
			if expires > 0 {
				t := time.Now().Add(expires)
				until = &t
			}
			g, err := a.GrantUntil(grantee, itemName, protocol.GrantLevel(level), until)
			if err != nil {
				return err
			}
			return encode(cmd, g)
		},
	}
	add.Flags().StringVar(&agentName, "agent", "", "agent id. XOR --human")
	add.Flags().StringVar(&humanName, "human", "", "Kratos identity id, or email resolved via glue. XOR --agent. Not a family vault.")
	add.Flags().StringVar(&itemName, "item", "", "item id")
	add.Flags().StringVar(&level, "level", "", "level1 (human last step) or level2 (agent exclusive)")
	add.Flags().DurationVar(&expires, "expires", 0, "grant lifetime. zero is forever")
	_ = add.MarkFlagRequired("item")
	_ = add.MarkFlagRequired("level")
	list := &cobra.Command{
		Use:   "list",
		Short: "List grants",
		RunE: func(cmd *cobra.Command, args []string) error {
			if originBase() != "" {
				return originGrantList(cmd)
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			grants, err := a.Store.ListGrants()
			if err != nil {
				return err
			}
			if grants == nil {
				grants = []protocol.Grant{}
			}
			return encode(cmd, grants)
		},
	}
	c.AddCommand(add, list)
	return c
}

func useCmd(home *string) *cobra.Command {
	var agentName, itemName, rawURL, method, tokenFile, bodyFile string
	var headers []string
	c := &cobra.Command{
		Use:   "use",
		Short: "Fetch as an agent. Secret is injected; it is not printed.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if originBase() != "" {
				return originUse(cmd, tokenFile, itemName, rawURL, method, headers, bodyFile)
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			if tokenFile != "" {
				raw, err := readFileMaterial(tokenFile)
				if err != nil {
					return err
				}
				agent, err := a.AgentFromOIDC(cmd.Context(), string(raw))
				if err != nil {
					return err
				}
				if agentName != "" && agentName != agent.ID {
					return fmt.Errorf("oidc token is agent %q, not %q", agent.ID, agentName)
				}
				agentName = agent.ID
			}
			if agentName == "" {
				return fmt.Errorf("--agent or --oidc-token-file is required")
			}
			fetch := protocol.Fetch{Method: method, URL: rawURL, Header: http.Header{}}
			for _, h := range headers {
				k, v, ok := strings.Cut(h, ":")
				if !ok || strings.TrimSpace(k) == "" {
					return fmt.Errorf("use: --header is Name: value")
				}
				fetch.Header.Add(strings.TrimSpace(k), strings.TrimSpace(v))
			}
			if bodyFile != "" {
				fetch.Body, err = os.ReadFile(bodyFile)
				if err != nil {
					return err
				}
			}
			got, err := a.UseFetch(cmd.Context(), agentName, itemName, fetch)
			if err != nil {
				return err
			}
			return encode(cmd, useView(got))
		},
	}
	c.Flags().StringVar(&agentName, "agent", "", "agent id")
	c.Flags().StringVar(&itemName, "item", "", "item id")
	c.Flags().StringVar(&rawURL, "url", "", "URL to fetch")
	c.Flags().StringVar(&method, "method", "GET", "HTTP method")
	c.Flags().StringArrayVar(&headers, "header", nil, "extra header Name: value. never the vault secret")
	c.Flags().StringVar(&bodyFile, "body-file", "", "request body file. never --body on argv")
	c.Flags().StringVar(&tokenFile, "oidc-token-file", "", "OIDC ID token file; resolves the agent. Never argv.")
	_ = c.MarkFlagRequired("item")
	_ = c.MarkFlagRequired("url")
	return c
}

func approveCmd(home *string) *cobra.Command {
	var ttl time.Duration
	var tokenFile string
	c := &cobra.Command{
		Use:   "approve GRANT_ID",
		Short: "Human last unlock for a level-1 grant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			raw, err := humanToken(tokenFile)
			if err != nil {
				return err
			}
			var ap protocol.Approval
			if raw != "" {
				ap, err = a.ApproveOIDC(cmd.Context(), args[0], raw, ttl)
			} else {
				ap, err = a.Approve(args[0], ttl)
			}
			if err != nil {
				return err
			}
			return encode(cmd, ap)
		},
	}
	c.Flags().DurationVar(&ttl, "ttl", 15*time.Minute, "approval lifetime")
	c.Flags().StringVar(&tokenFile, "oidc-token-file", "", "Hydra ID token file. Env PWM_HUMAN_TOKEN. Never argv.")
	return c
}

func humanToken(tokenFile string) (string, error) {
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	if f := strings.TrimSpace(os.Getenv("PWM_HUMAN_TOKEN_FILE")); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(os.Getenv("PWM_HUMAN_TOKEN")), nil
}

func proxyCmd(home *string) *cobra.Command {
	var agent, listen, tokenFile string
	c := &cobra.Command{
		Use:   "proxy",
		Short: "HTTPS_PROXY inject. Bound to --agent. Unknown hosts fail closed.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if agent == "" {
				agent = os.Getenv("PWM_AGENT")
			}
			if agent == "" {
				return fmt.Errorf("--agent or PWM_AGENT is required")
			}
			if originBase() != "" {
				return originProxyWait(cmd, *home, agent, tokenFile, listen)
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			s, err := proxy.New(a, agent, a.Dir)
			if err != nil {
				return err
			}
			if listen != "" {
				s.ListenAddr = listen
			}
			if err := s.Start(); err != nil {
				return err
			}
			defer s.Close()
			for _, e := range s.Env() {
				fmt.Fprintln(cmd.OutOrStdout(), e)
			}
			ctx := cmd.Context()
			ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
			defer stop()
			<-ctx.Done()
			return nil
		},
	}
	c.Flags().StringVar(&agent, "agent", "", "agent id (or PWM_AGENT)")
	c.Flags().StringVar(&listen, "listen", "127.0.0.1:0", "listen address")
	c.Flags().StringVar(&tokenFile, "oidc-token-file", "", "agent token file for PWM_ORIGIN. Never argv.")
	return c
}

func runCmd(home *string) *cobra.Command {
	var agent, tokenFile string
	var injects []string
	c := &cobra.Command{
		Use:   "run --agent NAME -- COMMAND [args...]",
		Short: "Run COMMAND with granted secrets in env and HTTP(S)_PROXY. Infisical vault run. Never the prompt.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if agent == "" {
				agent = os.Getenv("PWM_AGENT")
			}
			if agent == "" {
				return fmt.Errorf("--agent or PWM_AGENT is required")
			}
			if originBase() != "" {
				return originRun(cmd, *home, agent, tokenFile, injects, args)
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			s, err := proxy.New(a, agent, a.Dir)
			if err != nil {
				return err
			}
			if err := s.Start(); err != nil {
				return err
			}
			defer s.Close()
			pairs, err := a.ChildEnv(cmd.Context(), agent)
			if err != nil {
				return err
			}
			for _, spec := range injects {
				src, dest, err := parseInject(spec)
				if err != nil {
					return err
				}
				if err := a.InjectFile(src, dest, pairs); err != nil {
					return err
				}
			}
			proc := exec.CommandContext(cmd.Context(), args[0], args[1:]...)
			proc.Stdin = cmd.InOrStdin()
			proc.Stdout = cmd.OutOrStdout()
			proc.Stderr = cmd.ErrOrStderr()
			proc.Env = append(os.Environ(), s.Env()...)
			proc.Env = append(proc.Env, pairs...)
			return proc.Run()
		},
	}
	c.Flags().StringVar(&agent, "agent", "", "agent id (or PWM_AGENT)")
	c.Flags().StringArrayVar(&injects, "inject", nil, "template:dest. ${NAME} or pwm://name. dest is 0600. never stdout")
	c.Flags().StringVar(&tokenFile, "oidc-token-file", "", "agent token file for PWM_ORIGIN. Never argv.")
	return c
}

func parseInject(spec string) (src, dest string, err error) {
	src, dest, ok := strings.Cut(spec, ":")
	if !ok || src == "" || dest == "" {
		return "", "", fmt.Errorf("run: --inject is src:dest")
	}
	return src, dest, nil
}

func auditCmd(home *string) *cobra.Command {
	var tokenFile string
	c := &cobra.Command{
		Use:   "audit",
		Short: "Grant events for this actor. No secrets. Not MCP.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if originBase() != "" {
				return originEvents(cmd, tokenFile)
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			events, err := a.Store.Audit()
			if err != nil {
				return err
			}
			if events == nil {
				events = []protocol.AuditEvent{}
			}
			return encode(cmd, events)
		},
	}
	c.Flags().StringVar(&tokenFile, "oidc-token-file", "", "agent token file for PWM_ORIGIN. Never argv.")
	return c
}

func genCmd() *cobra.Command {
	var n int
	var outFile string
	c := &cobra.Command{
		Use:   "gen",
		Short: "Generate a password. Human CLI. Not MCP. Not a vault item until item add.",
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := passgen.New(n)
			if err != nil {
				return err
			}
			if outFile != "" {
				if err := os.WriteFile(outFile, append(b, '\n'), 0o600); err != nil {
					return err
				}
				return encode(cmd, map[string]bool{"ok": true})
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
			return err
		},
	}
	c.Flags().IntVar(&n, "length", 20, "length 12-128")
	c.Flags().StringVar(&outFile, "out-file", "", "write here instead of stdout. never argv.")
	return c
}

func totpCmd() *cobra.Command {
	c := &cobra.Command{Use: "totp", Short: "Enroll a TOTP seed. Human CLI. Not MCP."}
	var issuer, account, outFile, qrFile string
	enroll := &cobra.Command{
		Use:   "enroll",
		Short: "Write seed --out-file and otpauth QR --qr-file. Then item add --totp-file. Never stdout.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if outFile == "" || qrFile == "" {
				return fmt.Errorf("totp enroll: --out-file and --qr-file required")
			}
			got, err := totpenroll.Generate(issuer, account)
			if err != nil {
				return err
			}
			if err := os.WriteFile(outFile, append([]byte(got.Seed), '\n'), 0o600); err != nil {
				return err
			}
			if err := os.WriteFile(qrFile, got.PNG, 0o600); err != nil {
				return err
			}
			return encode(cmd, map[string]bool{"ok": true})
		},
	}
	enroll.Flags().StringVar(&issuer, "issuer", "Veil", "otpauth issuer")
	enroll.Flags().StringVar(&account, "account", "", "otpauth account, e.g. stripe")
	enroll.Flags().StringVar(&outFile, "out-file", "", "seed file. never argv. then item add --totp-file")
	enroll.Flags().StringVar(&qrFile, "qr-file", "", "otpauth QR PNG. not a screenshot of the seed")
	c.AddCommand(enroll)
	return c
}

func serveCmd(home *string) *cobra.Command {
	var path string
	c := &cobra.Command{
		Use:   "serve",
		Short: "Laptop socket. Same agent credential as cloud. Transport, not identity.",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			if path == "" {
				path = socket.DefaultPath(a.Dir)
			}
			s, err := socket.Listen(a, path)
			if err != nil {
				return err
			}
			defer s.Close()
			fmt.Fprintln(cmd.OutOrStdout(), s.Path)
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			<-ctx.Done()
			return nil
		},
	}
	c.Flags().StringVar(&path, "socket", "", "unix socket path (default <home>/pwm.sock)")
	return c
}

func fillCmd(home *string) *cobra.Command {
	c := &cobra.Command{
		Use:   "fill",
		Short: "keepassxc-browser native host. Fill writes into the page. Agents never see the secret.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if originBase() != "" {
				dir, err := resolveHome(*home)
				if err != nil {
					return err
				}
				if err := os.MkdirAll(dir, 0o700); err != nil {
					return err
				}
				tok, _ := originHumanToken()
				return fill.NewOrigin(dir, originBase(), tok).Serve(os.Stdin, os.Stdout)
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			return fill.New(a).Serve(os.Stdin, os.Stdout)
		},
	}
	c.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Install the native messaging host for the keepassxc-browser extension. Does not copy the extension.",
		RunE: func(cmd *cobra.Command, args []string) error {
			origin := originBase()
			if origin == "" {
				return fmt.Errorf("fill install: PWM_ORIGIN is required")
			}
			dir, err := resolveHome(*home)
			if err != nil {
				return err
			}
			user, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			bin, err := os.Executable()
			if err != nil {
				return err
			}
			if err := fill.InstallOrigin(bin, dir, user, origin); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), fill.NativeHostName)
			return nil
		},
	})
	return c
}

func sshCmd(home *string) *cobra.Command {
	var path string
	c := &cobra.Command{
		Use:   "ssh",
		Short: "OpenSSH agent socket. The broker signs. The private key never leaves.",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			if path == "" {
				path = sshagent.DefaultPath(a.Dir)
			}
			s, err := sshagent.Listen(a, path)
			if err != nil {
				return err
			}
			defer s.Close()
			fmt.Fprintf(cmd.OutOrStdout(), "SSH_AUTH_SOCK=%s\n", s.Path)
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			<-ctx.Done()
			return nil
		},
	}
	c.Flags().StringVar(&path, "socket", "", "unix socket path (default <home>/ssh.sock)")
	return c
}

func mcpCmd(home *string) *cobra.Command {
	var listen, publicURL string
	c := &cobra.Command{
		Use:   "mcp",
		Short: "Serve Streamable HTTP MCP. Bearer is the agent. Tools cannot return secrets.",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := openOrInitApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			listen = mcpserver.ListenAddr(listen, cmd.Flags().Changed("listen"))
			publicURL = mcpPublicURL(publicURL, listen)
			issuer := envOr("PWM_HYDRA_ISSUER", "http://127.0.0.1:4444")
			slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
				ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
					if a.Key == slog.LevelKey {
						a.Value = slog.StringValue(strings.ToLower(a.Value.String()))
					}
					return a
				},
			})))
			otelStop, err := otelsetup.Start(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = otelStop(context.Background()) }()
			srv := &http.Server{Addr: listen, Handler: mcpserver.Mux(a, publicURL, issuer)}
			fmt.Fprintln(cmd.OutOrStdout(), publicURL)
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			go func() {
				<-ctx.Done()
				_ = srv.Shutdown(context.Background())
			}()
			err = srv.ListenAndServe()
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		},
	}
	c.PersistentFlags().StringVar(&listen, "listen", mcpserver.DefaultAddr, "TCP address")
	c.PersistentFlags().StringVar(&publicURL, "url", "", "public MCP URL (default http://<listen>/mcp)")
	c.AddCommand(&cobra.Command{
		Use:   "config",
		Short: "Print remote MCP config. No secrets.",
		RunE: func(cmd *cobra.Command, args []string) error {
			listen = mcpserver.ListenAddr(listen, cmd.Flags().Changed("listen"))
			cfg, err := mcpserver.Config(mcpPublicURL(publicURL, listen))
			if err != nil {
				return err
			}
			return encode(cmd, cfg)
		},
	})
	c.AddCommand(&cobra.Command{
		Use:   "stdio",
		Short: "Laptop MCP for Cursor. Same tools as origin. Token from file, never argv.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			return runOriginMCPStdio(ctx)
		},
	})
	c.AddCommand(&cobra.Command{
		Use:   "laptop",
		Short: "Print Cursor MCP stdio block. No secrets.",
		RunE: func(cmd *cobra.Command, args []string) error {
			origin := originBase()
			if origin == "" {
				origin = "https://veil.nyc"
			}
			return encode(cmd, mcpserver.LaptopConfig(origin))
		},
	})
	return c
}

func mcpPublicURL(flag, listen string) string {
	if flag != "" {
		return flag
	}
	if v := envOr("PWM_MCP_URL", ""); v != "" {
		return v
	}
	if strings.HasPrefix(listen, "0.0.0.0:") || strings.HasPrefix(listen, "[::]:") {
		return mcpserver.DefaultPublicURL
	}
	return mcpserver.ResourceURL(listen)
}

type useDTO struct {
	Decision   protocol.Decision `json:"decision"`
	Reason     string            `json:"reason,omitempty"`
	ApprovalID string            `json:"approval_id,omitempty"`
	Status     int               `json:"status,omitempty"`
	Body       string            `json:"body,omitempty"`
}

func useView(got protocol.UseResult) useDTO {
	v := useDTO{Decision: got.Decision, Reason: got.Reason, ApprovalID: got.ApprovalID}
	if got.Fetch != nil {
		v.Status = got.Fetch.Status
		v.Body = string(got.Fetch.Body)
	}
	return v
}

func encode(cmd *cobra.Command, v any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func readItemMaterial(secretFile, totpFile string, stdin io.Reader) (token, totpSeed []byte, err error) {
	if totpFile != "" {
		totpSeed, err = readFileMaterial(totpFile)
		if err != nil {
			return nil, nil, err
		}
		if len(totpSeed) == 0 {
			return nil, nil, fmt.Errorf("empty totp seed")
		}
	}
	switch {
	case secretFile != "" && secretFile != "-":
		token, err = readFileMaterial(secretFile)
	case secretFile == "-" || totpFile == "":
		token, err = readStdinMaterial(stdin)
	}
	if err != nil {
		return nil, nil, err
	}
	if len(token) == 0 && len(totpSeed) == 0 {
		return nil, nil, fmt.Errorf("empty secret on stdin (use --secret-file)")
	}
	return token, totpSeed, nil
}

func readFileMaterial(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return trimNL(b), nil
}

func readStdinMaterial(stdin io.Reader) ([]byte, error) {
	b, err := io.ReadAll(stdin)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("empty secret on stdin (use --secret-file)")
	}
	return trimNL(b), nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
