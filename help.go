package main

import "fmt"

// Version is the FaultWall release version.
// Override at build time: go build -ldflags "-X main.Version=v0.3.0"
var Version = "dev"

func printRootHelp() {
	fmt.Println(`FaultWall — The Agentic Data Firewall for PostgreSQL

Usage:
  faultwall <command> [flags]
  faultwall --proxy [flags]        # run as inline proxy (main mode)

Commands:
  try          Zero-config monitor mode + live view (demo DB if no URL given)
  init         Scaffold a new faultwall.yaml policy file
  agent-url    Print a ready-to-use connection string
  version      Print version info
  help         Show this help

Proxy mode flags:
  --proxy                    Run in L7 proxy mode
  --listen ADDR              Proxy listen address (default :5433)
  --upstream ADDR            Real Postgres address (default localhost:5432)
  --policies FILE            Policy YAML (default ./policies.yaml)
  --tls-cert FILE            Client-facing TLS cert
  --tls-key FILE             Client-facing TLS key
  --upstream-tls             Connect upstream using TLS
  --upstream-tls-skip-verify Skip upstream TLS verification

Fastest start (no YAML, never blocks):
  faultwall try                               # demo Postgres + demo agent
  faultwall try postgres://user:pass@host/db  # your DB, monitor mode

Quick start (enforce):
  faultwall init                              # create policy file
  faultwall --proxy --policies faultwall.yaml # start proxy
  faultwall agent-url                         # copy connection string

Docs: https://github.com/shreyasXV/faultwall`)
}
