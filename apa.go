package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/shreyasXV/faultwall/policygen/agent"
)

// runAPA dispatches the `faultwall apa` subcommand.
//
//	faultwall apa run [flags]     — execute one APA cycle and exit
//	faultwall apa serve [flags]   — run APA on a cron schedule (default: hourly)
//
func runAPA(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: faultwall apa <run|serve> [flags]\n\n" +
			"  run     Run one APA cycle and exit\n" +
			"  serve   Run APA on the configured cron schedule\n")
	}

	subcmd, rest := args[0], args[1:]
	switch subcmd {
	case "run":
		return runAPADispatch(rest, true)
	case "serve":
		return runAPADispatch(rest, false)
	case "-h", "--help", "help":
		fmt.Println("usage: faultwall apa <run|serve> [flags]")
		fmt.Println("  --policy <path>        override policy file (default: ./policies.yaml or POLICY_FILE)")
		fmt.Println("  --observations <path>  override observations.jsonl path")
		fmt.Println("  --provider <name>      override apa.provider (openai|litellm|anthropic|fake)")
		return nil
	default:
		return fmt.Errorf("unknown apa subcommand %q (want: run|serve)", subcmd)
	}
}

// runAPADispatch parses common flags, loads config, and either runs once or serves.
func runAPADispatch(args []string, runOnce bool) error {
	name := "apa run"
	if !runOnce {
		name = "apa serve"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	policyFlag := fs.String("policy", "", "path to policies.yaml (defaults to POLICY_FILE env or ./policies.yaml)")
	obsFlag := fs.String("observations", "", "path to observations.jsonl (defaults to OBSERVATION_PATH env or ~/.faultwall/observations.jsonl)")
	providerFlag := fs.String("provider", "", "override apa.provider from policy file (openai|anthropic|fake)")
	// --once is a legacy alias accepted for back-compat with earlier UX.
	onceLegacy := fs.Bool("once", false, "deprecated — 'apa run' is already one-shot")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *onceLegacy && !runOnce {
		runOnce = true // tolerate `apa serve --once` as one-shot
	}

	policyPath := *policyFlag
	if policyPath == "" {
		policyPath = os.Getenv("POLICY_FILE")
	}
	if policyPath == "" {
		policyPath = "./policies.yaml"
	}
	obsPath := *obsFlag
	if obsPath == "" {
		obsPath = os.Getenv("OBSERVATION_PATH")
	}
	if obsPath == "" {
		home, _ := os.UserHomeDir()
		obsPath = home + "/.faultwall/observations.jsonl"
	}
	auditPath := os.Getenv("APA_AUDIT_LOG")
	if auditPath == "" {
		home, _ := os.UserHomeDir()
		auditPath = home + "/.faultwall/apa_audit.jsonl"
	}

	cfg, err := agent.LoadConfig(policyPath, obsPath, auditPath)
	if err != nil {
		return fmt.Errorf("load apa config: %w", err)
	}
	if *providerFlag != "" {
		cfg.Provider = *providerFlag
	}

	// If a control plane is configured (~/.faultwall/config.toml [control_plane]
	// or env), also ship each proposed diff to its review queue (POST
	// /v1/apa/propose). Metadata + diff only; off the APA cron path. PRs are
	// still opened as before — this is additive.
	if cpCfg, ok := loadControlPlaneConfig(); ok || (cpCfg.URL != "" && cpCfg.Token != "") {
		if apaClient := NewAPAProposalClient(cpCfg); apaClient != nil {
			cfg.Sink = apaClient.Sink()
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if runOnce {
		return runAPAOnce(ctx, cfg)
	}
	return runAPAServe(ctx, cfg)
}

func runAPAOnce(ctx context.Context, cfg agent.APAConfig) error {
	urls, err := agent.RunOnce(ctx, cfg)
	if err != nil {
		return err
	}
	if len(urls) == 0 {
		fmt.Println("[apa] run complete — no PRs opened")
	} else {
		for _, u := range urls {
			fmt.Println("[apa] PR opened:", u)
		}
	}
	return nil
}

func runAPAServe(ctx context.Context, cfg agent.APAConfig) error {
	interval := cfg.Window
	if interval < time.Minute {
		interval = time.Hour
	}
	fmt.Printf("[apa] starting cron loop (interval: %s, provider: %s)\n", interval, cfg.Provider)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run immediately on startup.
	if err := runAPAOnce(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "[apa] cycle error: %v\n", err)
	}

	for {
		select {
		case <-ctx.Done():
			fmt.Println("[apa] shutting down")
			return nil
		case <-ticker.C:
			if err := runAPAOnce(ctx, cfg); err != nil {
				fmt.Fprintf(os.Stderr, "[apa] cycle error: %v\n", err)
			}
		}
	}
}
