package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/shreyasXV/faultwall/policygen/agent"
)

// runAPA dispatches the `faultwall apa` subcommand.
//
//	faultwall apa run --once   — execute one APA cycle and exit
//	faultwall apa serve        — run APA on a cron schedule (default: hourly)
func runAPA(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: faultwall apa <run|serve> [flags]\n\n" +
			"  run --once   Run one APA cycle and exit\n" +
			"  serve        Run APA on the configured cron schedule\n")
	}

	policyPath := os.Getenv("POLICY_FILE")
	if policyPath == "" {
		policyPath = "./policies.yaml"
	}
	obsPath := os.Getenv("OBSERVATION_PATH")
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

	// Allow --provider and --once flags to override the YAML config.
	var runOnce bool
	for i, arg := range args {
		switch arg {
		case "--once":
			runOnce = true
		case "--provider":
			if i+1 < len(args) {
				cfg.Provider = args[i+1]
			}
		case "--policy":
			if i+1 < len(args) {
				cfg.PolicyPath = args[i+1]
			}
		case "--observations":
			if i+1 < len(args) {
				cfg.ObservationPath = args[i+1]
			}
		}
	}

	switch args[0] {
	case "run":
		runOnce = true
	case "serve":
		runOnce = false
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
