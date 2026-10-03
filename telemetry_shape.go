package main

// telemetry_shape.go — literal-free query shape ("fingerprint text") for the
// hosted activity feed.
//
// PRIVACY: the shape is the ONLY query-derived text that may leave the box,
// and only when FW_TELEMETRY_QUERY_SHAPE is on (see telemetry_client.go).
// It is built from the pg_query scanner's token stream, not from regexes and
// not from pg_query.Normalize: Normalize leaves literals in place for DDL
// defaults, COMMENT ON, COPY file paths, PREPARE bodies and SQL comments.
// Here every constant token (string, dollar-quoted, E'', U&'', bit, hex,
// integer, float, $n param, TRUE/FALSE) becomes "?", and comments are
// dropped entirely. If the query cannot be tokenized, the shape is empty.
// We never fall back to sending raw text.
//
//   UPDATE orders SET status = 'refunded' WHERE id = 4412 -- ticket 991
//   -> UPDATE orders SET status = ? WHERE id = ?

import (
	"regexp"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// maxQueryShapeLen bounds the shape we ship (bytes).
const maxQueryShapeLen = 1024

// longParamListRe collapses `?, ?, ?, …` runs longer than 10 so IN-lists of
// different lengths share a shape and bulk VALUES lists stay short.
var longParamListRe = regexp.MustCompile(`\?(?:\s*,\s*\?){10,}`)

// normalizeQueryShape returns the literal-free shape of query, or "" if it
// cannot be safely produced.
func normalizeQueryShape(query string) string {
	q := sanitizeQuery(query)
	if q == "" {
		return ""
	}
	res, err := pg_query.Scan(q)
	if err != nil || res == nil {
		return ""
	}
	var b strings.Builder
	prevEnd := int32(-1)
	for _, tk := range res.Tokens {
		if tk.Start < 0 || tk.End > int32(len(q)) || tk.Start > tk.End {
			return ""
		}
		var piece string
		switch tk.Token {
		case pg_query.Token_SQL_COMMENT, pg_query.Token_C_COMMENT:
			continue // comments can carry anything (ticket ids, emails, values)
		case pg_query.Token_SCONST, pg_query.Token_USCONST, pg_query.Token_BCONST,
			pg_query.Token_XCONST, pg_query.Token_ICONST, pg_query.Token_FCONST,
			pg_query.Token_PARAM, pg_query.Token_TRUE_P, pg_query.Token_FALSE_P:
			piece = "?"
		default:
			piece = q[tk.Start:tk.End]
		}
		if prevEnd >= 0 && tk.Start > prevEnd {
			b.WriteByte(' ')
		}
		b.WriteString(piece)
		prevEnd = tk.End
		if b.Len() > maxQueryShapeLen*2 {
			break // truncated below; stop scanning huge statements early
		}
	}
	out := longParamListRe.ReplaceAllString(b.String(), "?, ...")
	if len(out) > maxQueryShapeLen {
		cut := maxQueryShapeLen
		for cut > 0 && out[cut-1]&0xC0 == 0x80 { // don't split a UTF-8 rune
			cut--
		}
		if cut > 0 && out[cut-1]&0xC0 == 0xC0 {
			cut--
		}
		out = out[:cut] + " ..."
	}
	// Defense in depth: anything that still looks like a quoted literal means
	// the scanner saw something we didn't expect. Ship nothing.
	if strings.ContainsAny(out, "'") || strings.Contains(out, "$$") {
		return ""
	}
	return out
}
