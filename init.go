package main

import (
	"bufio"
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

//go:embed templates/policies/*.yaml
var policyTemplates embed.FS

// runInit scaffolds a new faultwall.yaml in the current directory
// based on a named template (balanced | strict | permissive).
// If no flags are passed and stdin is a TTY, runs an interactive wizard
// to ask the user for the agent name and policy template.
func runInit(args []string) error {
	template := ""
	output := "faultwall.yaml"
	force := false
	agentName := ""
	interactive := false
	noInteractive := false

	for i, arg := range args {
		switch arg {
		case "--strict":
			template = "strict"
		case "--permissive":
			template = "permissive"
		case "--balanced":
			template = "balanced"
		case "--template":
			if i+1 < len(args) {
				template = args[i+1]
			}
		case "-o", "--output":
			if i+1 < len(args) {
				output = args[i+1]
			}
		case "-f", "--force":
			force = true
		case "--agent":
			if i+1 < len(args) {
				agentName = args[i+1]
			}
		case "-i", "--interactive":
			interactive = true
		case "--no-interactive":
			noInteractive = true
		case "-h", "--help":
			printInitHelp()
			return nil
		}
	}

	// Interactive wizard if no template/agent provided and stdin is a TTY
	if !noInteractive && (interactive || (template == "" && agentName == "" && isTTY(os.Stdin))) {
		wizardTemplate, wizardAgent, err := runInitWizard()
		if err != nil {
			return err
		}
		if template == "" {
			template = wizardTemplate
		}
		if agentName == "" {
			agentName = wizardAgent
		}
	}

	// Apply defaults if still unset
	if template == "" {
		template = "balanced"
	}
	if agentName == "" {
		agentName = "my-agent"
	}

	// Validate agent name (no spaces, no colons — these break application_name parsing)
	if strings.ContainsAny(agentName, ": \t\n") {
		return fmt.Errorf("agent name %q contains invalid characters (no spaces, colons)", agentName)
	}

	// Check destination
	if _, err := os.Stat(output); err == nil && !force {
		return fmt.Errorf("%s already exists (use --force to overwrite)", output)
	}

	// Load embedded template
	src := fmt.Sprintf("templates/policies/%s.yaml", template)
	data, err := policyTemplates.ReadFile(src)
	if err != nil {
		valid := []string{"balanced", "strict", "permissive"}
		return fmt.Errorf("unknown template %q (valid: %s)", template, strings.Join(valid, ", "))
	}

	// Substitute my-agent → user-provided agent name
	rendered := strings.ReplaceAll(string(data), "my-agent", agentName)

	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil && output != filepath.Base(output) {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

	f, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", output, err)
	}
	defer f.Close()
	if _, err := io.Copy(f, strings.NewReader(rendered)); err != nil {
		return fmt.Errorf("failed to write %s: %w", output, err)
	}

	fmt.Printf("Created %s (%s template, agent: %s)\n", output, template, agentName)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Start FaultWall:")
	fmt.Printf("       faultwall --proxy --policies %s\n", output)
	fmt.Println("  2. Get your agent connection string:")
	fmt.Printf("       faultwall agent-url --agent %s --mission default\n", agentName)
	fmt.Println("  3. Point your psql/app at port 5433 with that connection string.")
	fmt.Println()
	return nil
}

// isTTY checks if the given file is a terminal (for interactive wizard detection).
func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

// runInitWizard walks the user through choosing a policy template + agent name.
func runInitWizard() (template, agent string, err error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("FaultWall Setup Wizard")
	fmt.Println()
	fmt.Println("Let's configure your policy file. Press Ctrl+C to cancel.")
	fmt.Println()

	// 1. Policy template
	fmt.Println("Which policy template?")
	fmt.Println("  [1] balanced     — blocks destructive ops, allows reads/writes (default)")
	fmt.Println("  [2] strict       — read-only, blocks ALL writes")
	fmt.Println("  [3] permissive   — only blocks catastrophic ops (DROP/TRUNCATE/GRANT)")
	fmt.Print("\nChoose [1-3, default 1]: ")
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", "", fmt.Errorf("failed to read input: %w", err)
	}
	choice := strings.TrimSpace(line)
	switch choice {
	case "", "1", "balanced":
		template = "balanced"
	case "2", "strict":
		template = "strict"
	case "3", "permissive":
		template = "permissive"
	default:
		fmt.Printf("WARN: unknown choice %q, defaulting to balanced\n", choice)
		template = "balanced"
	}
	fmt.Printf("  → %s\n\n", template)

	// 2. Agent name
	fmt.Println("What's your agent's name?")
	fmt.Println("  This becomes the identity in your connection string:")
	fmt.Println("  postgres://...?application_name=agent:<NAME>:mission:default")
	fmt.Println()
	fmt.Println("  Examples: cursor-ai, langchain-bot, my-research-agent")
	fmt.Print("\nAgent name [default: my-agent]: ")
	line, err = reader.ReadString('\n')
	if err != nil {
		return "", "", fmt.Errorf("failed to read input: %w", err)
	}
	agent = strings.TrimSpace(line)
	if agent == "" {
		agent = "my-agent"
	}
	if strings.ContainsAny(agent, ": \t") {
		fmt.Printf("WARN: invalid characters (spaces/colons), using 'my-agent'\n")
		agent = "my-agent"
	}
	fmt.Printf("  → %s\n\n", agent)

	return template, agent, nil
}

func printInitHelp() {
	fmt.Println(`faultwall init — scaffold a new policy file

Usage:
  faultwall init                   # interactive wizard (default when TTY)
  faultwall init [flags]           # non-interactive with flags

Flags:
  --balanced        Balanced policy (blocks destructive ops)
  --strict          Read-only policy (blocks all writes)
  --permissive      Catastrophic-only (blocks DROP/TRUNCATE/GRANT)
  --template NAME   Explicit template name (balanced|strict|permissive)
  --agent NAME      Agent name (replaces "my-agent" in template)
  -o, --output      Output filename (default: faultwall.yaml)
  -f, --force       Overwrite existing file
  -i, --interactive Force wizard even if flags supplied
  --no-interactive  Skip wizard (use flags/defaults)
  -h, --help        Show this help

Examples:
  faultwall init                                    # interactive wizard
  faultwall init --balanced --agent cursor-ai       # non-interactive
  faultwall init --strict -o prod.yaml              # strict, custom path`)
}

// runAgentURL prints a ready-to-use postgres connection string.
// By default the password is masked (***) to avoid credential leaks when the
// output is piped into logs/CI. Pass --password <value> to render a real one,
// or --env to emit an `export DATABASE_URL=...` line for shell use.
func runAgentURL(args []string) error {
	agent := "my-agent"
	mission := "default"
	host := "localhost"
	port := "5433"
	user := "postgres"
	pass := ""
	db := "postgres"
	envMode := false

	for i, arg := range args {
		switch arg {
		case "--agent":
			if i+1 < len(args) {
				agent = args[i+1]
			}
		case "--mission":
			if i+1 < len(args) {
				mission = args[i+1]
			}
		case "--host":
			if i+1 < len(args) {
				host = args[i+1]
			}
		case "--port":
			if i+1 < len(args) {
				port = args[i+1]
			}
		case "--user":
			if i+1 < len(args) {
				user = args[i+1]
			}
		case "--password":
			if i+1 < len(args) {
				pass = args[i+1]
			}
		case "--db":
			if i+1 < len(args) {
				db = args[i+1]
			}
		case "--env":
			envMode = true
		case "-h", "--help":
			fmt.Println(`faultwall agent-url — print a ready-to-use connection string

Usage:
  faultwall agent-url [flags]

Flags:
  --agent NAME       Agent name (default: my-agent)
  --mission NAME     Mission name (default: default)
  --host HOST        DB host (default: localhost)
  --port PORT        FaultWall proxy port (default: 5433)
  --user USER        DB user (default: postgres)
  --password PASS    DB password (omit to render as ***)
  --db DBNAME        Database name (default: postgres)
  --env              Print as 'export DATABASE_URL=...' for shell eval

By default, the password is masked with *** so the output is safe to paste
into docs or CI logs. Replace *** with the real password before using, or
pass --password to render it directly.`)
			return nil
		}
	}

	appName := fmt.Sprintf("agent:%s:mission:%s", agent, mission)
	displayPass := pass
	masked := false
	if displayPass == "" {
		displayPass = "***"
		masked = true
	}
	url := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?application_name=%s",
		user, displayPass, host, port, db, appName)

	if envMode {
		fmt.Printf("export DATABASE_URL=%q\n", url)
	} else {
		fmt.Println(url)
	}
	if masked {
		fmt.Fprintln(os.Stderr, "# Password masked as ***. Pass --password <value> to render it, or replace *** manually.")
	}
	return nil
}
