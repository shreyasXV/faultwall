package main

import (
	"fmt"
	"strings"
)

// resolveProxyEnforcement picks the --proxy enforcement mode.
// Precedence: --mode/--monitor flag > POLICY_ENFORCEMENT env > "enforce".
// Accepted: enforce | monitor (aliases: block → enforce; watch, observe → monitor).
// An invalid flag is a hard error; an invalid env value falls back to enforce
// (fail closed) with a warning.
func resolveProxyEnforcement(flag, env string) (mode, warning string, err error) {
	norm := func(v string) (string, bool) {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "enforce", "block":
			return "enforce", true
		case "monitor", "watch", "observe":
			return "monitor", true
		}
		return "", false
	}
	if flag != "" {
		m, ok := norm(flag)
		if !ok {
			return "", "", fmt.Errorf("invalid --mode %q (use enforce or monitor)", flag)
		}
		return m, "", nil
	}
	if strings.TrimSpace(env) != "" {
		m, ok := norm(env)
		if !ok {
			return "enforce", fmt.Sprintf("POLICY_ENFORCEMENT=%q is not enforce|monitor — defaulting to enforce (fail closed)", env), nil
		}
		return m, "", nil
	}
	return "enforce", "", nil
}
