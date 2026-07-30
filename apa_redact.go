package main

import (
	"regexp"
	"strings"
)

// redactedSQLSentinel replaces every `sql:` value in an APA policy diff before
// the diff is uploaded to the control plane.
const redactedSQLSentinel = "[redacted: query text stays on-host]"

// sqlKeyLine matches a `sql:` mapping line inside a policies.yaml
// FingerprintRule, including its unified-diff prefix (' ', '+', '-') and
// indentation. Capture 1 is everything up to and including "sql:".
//
// Both plain and quoted scalar forms are covered because the value (capture 2)
// is discarded wholesale rather than parsed.
var sqlKeyLine = regexp.MustCompile(`(?m)^([-+ ]?\s*(?:- )?sql:)[ \t]*(.*)$`)

// sqlBlockScalarLine matches the opening of a YAML block scalar for `sql:`
// (`sql: |`, `sql: >-`, etc.), whose value spans following, more-indented lines.
var sqlBlockScalarLine = regexp.MustCompile(`(?m)^([-+ ]?)(\s*(?:- )?)sql:[ \t]*[|>][-+0-9]*[ \t]*$`)

// redactSQLFromYAMLDiff strips customer query text out of an APA policy YAML
// diff while leaving the diff structurally intact and reviewable.
//
// Why this exists: a FingerprintRule in policies.yaml stores the raw observed
// query in its `sql:` field (see observation.go recordObservation, which passes
// the literal query string). An APA proposal that promotes fingerprints
// therefore produces a diff whose added lines contain real SQL: table names,
// WHERE predicates, and any literals the agent inlined. Uploading that to the
// control plane would exfiltrate customer query text, which the product
// explicitly promises never leaves the host.
//
// The hash, seen count, verdict, and reason all survive, so a human reviewing in
// the dashboard still sees which fingerprints are being promoted and why. To
// read the actual SQL they use the local file-drop artifact, which never leaves
// their infrastructure.
func redactSQLFromYAMLDiff(diff string) string {
	if diff == "" {
		return ""
	}

	// Pass 1: block scalars. Replace the `sql: |` header with an inline
	// sentinel and drop the continuation lines that carry the query body.
	if sqlBlockScalarLine.MatchString(diff) {
		diff = redactBlockScalars(diff)
	}

	// Pass 2: single-line scalars, quoted or bare.
	return sqlKeyLine.ReplaceAllString(diff, "${1} "+redactedSQLSentinel)
}

// redactBlockScalars handles the multi-line `sql: |` form. Continuation lines
// are those indented deeper than the `sql:` key itself; they are removed
// entirely so no query fragment survives.
func redactBlockScalars(diff string) string {
	lines := strings.Split(diff, "\n")
	out := make([]string, 0, len(lines))

	for i := 0; i < len(lines); i++ {
		m := sqlBlockScalarLine.FindStringSubmatch(lines[i])
		if m == nil {
			out = append(out, lines[i])
			continue
		}

		diffPrefix, indent := m[1], m[2]
		out = append(out, diffPrefix+indent+"sql: "+redactedSQLSentinel)

		keyIndent := len(strings.TrimRight(indent, "")) // indent width of the key
		// Skip continuation lines: same diff prefix, strictly deeper indent.
		for i+1 < len(lines) {
			next := lines[i+1]
			body := next
			if len(body) > 0 && (body[0] == '+' || body[0] == '-' || body[0] == ' ') {
				body = body[1:]
			}
			if strings.TrimSpace(body) == "" {
				break
			}
			if indentWidth(body) <= keyIndent {
				break
			}
			i++
		}
	}
	return strings.Join(out, "\n")
}

// indentWidth counts leading spaces, treating a tab as one level.
func indentWidth(s string) int {
	n := 0
	for _, r := range s {
		if r == ' ' {
			n++
			continue
		}
		if r == '\t' {
			n += 2
			continue
		}
		break
	}
	return n
}

// containsSQLValue reports whether a YAML/diff blob still carries a non-redacted
// `sql:` value. Used by tests and by the runtime self-check to prove redaction
// held before anything is uploaded.
func containsSQLValue(s string) bool {
	for _, m := range sqlKeyLine.FindAllStringSubmatch(s, -1) {
		v := strings.TrimSpace(m[2])
		if v == "" || v == redactedSQLSentinel {
			continue
		}
		return true
	}
	return sqlBlockScalarLine.MatchString(s)
}
