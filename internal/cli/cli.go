// Package cli is the human surface. Stolen shape from MeowPass: cobra, stdin
// for secrets, no `get` that prints material. Agents use MCP, not these commands.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/vortexnyc/password-manager/internal/app"
	"github.com/vortexnyc/password-manager/internal/mcpserver"
	"github.com/vortexnyc/password-manager/internal/protocol"
)

func New(version string) *cobra.Command {
	var home string
	root := &cobra.Command{
		Use:           "password-manager",
		Short:         "Agent-first credential broker. Agents never hold secrets.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	root.PersistentFlags().StringVar(&home, "home", "", "vault directory (env PWM_HOME, default ~/.password-manager)")
	root.SetVersionTemplate("{{.Version}}\n")

	root.AddCommand(initCmd(&home))
	root.AddCommand(itemCmd(&home))
	root.AddCommand(agentCmd(&home))
	root.AddCommand(grantCmd(&home))
	root.AddCommand(useCmd(&home))
	root.AddCommand(approveCmd(&home))
	root.AddCommand(mcpCmd(&home))
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

func openApp(home string) (*app.App, error) {
	dir, err := resolveHome(home)
	if err != nil {
		return nil, err
	}
	return app.Open(dir)
}

func initCmd(home *string) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create a local vault (org of one)",
		RunE: func(cmd *cobra.Command, args []string) error {
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

func itemCmd(home *string) *cobra.Command {
	c := &cobra.Command{Use: "item", Short: "Items (metadata only on list)"}
	var uri, secretFile string
	add := &cobra.Command{
		Use:   "add NAME",
		Short: "Store an API key. Secret from --secret-file or stdin. Never argv.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			secret, err := readSecret(secretFile, cmd.InOrStdin())
			if err != nil {
				return err
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			item, err := a.AddItem(args[0], uri, secret)
			if err != nil {
				return err
			}
			return encode(cmd, item)
		},
	}
	add.Flags().StringVar(&uri, "uri", "", "host this item may be used against, e.g. https://api.stripe.com")
	add.Flags().StringVar(&secretFile, "secret-file", "", "file containing the secret (`-` for stdin)")
	list := &cobra.Command{
		Use:   "list",
		Short: "List items (no secrets)",
		RunE: func(cmd *cobra.Command, args []string) error {
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
	c.AddCommand(add, list)
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
	return c
}

func grantCmd(home *string) *cobra.Command {
	c := &cobra.Command{Use: "grant", Short: "Per-item agent grants"}
	var agentName, itemName, level string
	add := &cobra.Command{
		Use:   "add",
		Short: "Grant an agent Use on an item (level1 or level2)",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			g, err := a.AddGrant(agentName, itemName, protocol.GrantLevel(level))
			if err != nil {
				return err
			}
			return encode(cmd, g)
		},
	}
	add.Flags().StringVar(&agentName, "agent", "", "agent id")
	add.Flags().StringVar(&itemName, "item", "", "item id")
	add.Flags().StringVar(&level, "level", "", "level1 (human last step) or level2 (agent exclusive)")
	_ = add.MarkFlagRequired("agent")
	_ = add.MarkFlagRequired("item")
	_ = add.MarkFlagRequired("level")
	list := &cobra.Command{
		Use:   "list",
		Short: "List grants",
		RunE: func(cmd *cobra.Command, args []string) error {
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
	var agentName, itemName, rawURL, method string
	c := &cobra.Command{
		Use:   "use",
		Short: "Fetch as an agent. Secret is injected; it is not printed.",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			got, err := a.Use(cmd.Context(), agentName, itemName, method, rawURL)
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
	_ = c.MarkFlagRequired("agent")
	_ = c.MarkFlagRequired("item")
	_ = c.MarkFlagRequired("url")
	return c
}

func approveCmd(home *string) *cobra.Command {
	var ttl time.Duration
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
			ap, err := a.Approve(args[0], ttl)
			if err != nil {
				return err
			}
			return encode(cmd, ap)
		},
	}
	c.Flags().DurationVar(&ttl, "ttl", 15*time.Minute, "approval lifetime")
	return c
}

func mcpCmd(home *string) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run MCP over stdio as PWM_AGENT. Tools cannot return secrets.",
		RunE: func(cmd *cobra.Command, args []string) error {
			agentID := os.Getenv("PWM_AGENT")
			if agentID == "" {
				return fmt.Errorf("PWM_AGENT is required")
			}
			a, err := openApp(*home)
			if err != nil {
				return err
			}
			defer a.Close()
			return mcpserver.Run(cmd.Context(), a, agentID)
		},
	}
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

func readSecret(path string, stdin io.Reader) ([]byte, error) {
	if path == "" || path == "-" {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			return nil, fmt.Errorf("empty secret on stdin (use --secret-file)")
		}
		return trimNL(b), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return trimNL(b), nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
