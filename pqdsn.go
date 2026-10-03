package main

// pqdsn.go — make libpq-style DSNs safe for github.com/lib/pq.
//
// lib/pq only understands sslmode=disable|require|verify-ca|verify-full and
// defaults to "require" when sslmode is absent. libpq (psql, psycopg, pgx, and
// every connection string users copy from a cloud console) also accepts
// "prefer" (the libpq default) and "allow". Handing those to lib/pq fails with
//
//	pq: unsupported sslmode "prefer"; only "require" (default), "verify-full",
//	"verify-ca", and "disable" supported
//
// which took down monitor mode and the QWM live-state sampler. We resolve
// prefer/allow/unset the way libpq would: probe the server with an
// SSLRequest, use "require" if it offers TLS, otherwise "disable".

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// serverSupportsTLS sends a Postgres SSLRequest and reports whether the
// server answered 'S'. Overridable in tests.
var serverSupportsTLS = func(addr string, timeout time.Duration) (bool, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	var req [8]byte
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], 80877103)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req[:]); err != nil {
		return false, err
	}
	var resp [1]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return false, err
	}
	switch resp[0] {
	case 'S':
		return true, nil
	case 'N':
		return false, nil
	default:
		return false, fmt.Errorf("unexpected SSLRequest response 0x%02X", resp[0])
	}
}

var kvSSLModeRe = regexp.MustCompile(`(^|\s)sslmode\s*=\s*'?([A-Za-z-]*)'?`)
var kvParamRe = regexp.MustCompile(`(?:^|\s)(host|hostaddr|port)\s*=\s*'?([^'\s]*)'?`)

// resolveSSLModeForPQ maps a libpq sslmode to one lib/pq supports, probing
// host:port when needed. Returns the mode and whether it changed.
func resolveSSLModeForPQ(mode, host, port string) (string, bool) {
	m := strings.ToLower(strings.TrimSpace(mode))
	switch m {
	case "disable", "require", "verify-ca", "verify-full":
		return m, m != mode
	}
	// prefer / allow / unset (lib/pq would treat unset as "require", which
	// breaks every non-TLS local Postgres).
	if host == "" {
		host = "localhost"
	}
	if i := strings.IndexByte(host, ','); i >= 0 { // multi-host: probe the first
		host = host[:i]
	}
	if port == "" {
		port = "5432"
	}
	if i := strings.IndexByte(port, ','); i >= 0 {
		port = port[:i]
	}
	if strings.HasPrefix(host, "/") { // unix socket: TLS never applies
		return "disable", true
	}
	ok, err := serverSupportsTLS(net.JoinHostPort(host, port), 3*time.Second)
	if err != nil {
		// Unreachable right now: be conservative off-box, permissive on loopback.
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return "disable", true
		}
		return "require", true
	}
	if ok {
		return "require", true
	}
	return "disable", true
}

// normalizeLibPQSSLMode rewrites a URL or keyword/value DSN so lib/pq accepts
// its sslmode. DSNs that already use a supported mode are returned unchanged.
func normalizeLibPQSSLMode(dsn string) string {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return dsn
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return dsn
		}
		q := u.Query()
		host := u.Hostname()
		if h := q.Get("host"); h != "" {
			host = h
		}
		mode, changed := resolveSSLModeForPQ(q.Get("sslmode"), host, u.Port())
		if !changed {
			return dsn
		}
		q.Set("sslmode", mode)
		u.RawQuery = q.Encode()
		return u.String()
	}
	// keyword/value form: "host=x port=5432 user=u sslmode=prefer"
	var host, port string
	for _, m := range kvParamRe.FindAllStringSubmatch(dsn, -1) {
		switch m[1] {
		case "host":
			host = m[2]
		case "hostaddr":
			if host == "" {
				host = m[2]
			}
		case "port":
			port = m[2]
		}
	}
	cur := ""
	if m := kvSSLModeRe.FindStringSubmatch(dsn); m != nil {
		cur = m[2]
	}
	mode, changed := resolveSSLModeForPQ(cur, host, port)
	if !changed {
		return dsn
	}
	if kvSSLModeRe.MatchString(dsn) {
		return kvSSLModeRe.ReplaceAllString(dsn, "${1}sslmode="+mode)
	}
	return dsn + " sslmode=" + mode
}

// sslModeOf returns the sslmode in a DSN (for logging; never logs the DSN).
func sslModeOf(dsn string) string {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		if u, err := url.Parse(dsn); err == nil {
			return u.Query().Get("sslmode")
		}
		return ""
	}
	if m := kvSSLModeRe.FindStringSubmatch(dsn); m != nil {
		return m[2]
	}
	return ""
}
