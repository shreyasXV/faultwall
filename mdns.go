package main

// Minimal, dependency-free mDNS (multicast DNS) responder so the local
// dashboard is reachable at a friendly name like http://faultwall.local:8080
// instead of http://localhost:8080 — with ZERO setup on the customer's side.
//
// We answer A queries for our advertised hostname (default "faultwall.local")
// with 127.0.0.1. This is intentionally tiny: it only handles the one record
// type we need and ignores everything else. macOS (Bonjour) and most Linux
// (Avahi/systemd-resolved) resolve .local names via mDNS out of the box, so a
// browser on the same machine just works. If mDNS is unavailable, the proxy
// still serves on localhost — this is a pure convenience layer that never
// blocks startup.

import (
	"fmt"
	"log"
	"net"
	"strings"
)

const (
	mdnsAddr  = "224.0.0.251:5353"
	mdnsTTL   = 120
	defaultLocalHost = "faultwall.local"
)

// startMDNSResponder advertises hostName (e.g. "faultwall.local") -> 127.0.0.1
// on the local network via mDNS. Runs in the background; returns immediately.
// Best-effort: any failure is logged at debug level and ignored.
func startMDNSResponder(hostName string) {
	hostName = strings.TrimSuffix(strings.ToLower(hostName), ".")
	if hostName == "" {
		hostName = defaultLocalHost
	}

	go func() {
		group, err := net.ResolveUDPAddr("udp4", mdnsAddr)
		if err != nil {
			return
		}
		conn, err := net.ListenMulticastUDP("udp4", nil, group)
		if err != nil {
			// mDNS port busy or no multicast iface — fine, localhost still works.
			return
		}
		defer conn.Close()
		_ = conn.SetReadBuffer(65536)

		buf := make([]byte, 1500)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			qname, qid, ok := parseMDNSQuestion(buf[:n], hostName)
			if !ok {
				continue
			}
			resp := buildMDNSAnswer(qid, qname, net.IPv4(127, 0, 0, 1))
			if resp != nil {
				_, _ = conn.WriteToUDP(resp, src)
				// Also send to the multicast group so resolvers caching see it.
				_, _ = conn.WriteToUDP(resp, group)
			}
		}
	}()
}

// parseMDNSQuestion does a minimal DNS-message parse, returning the queried
// name + transaction id when the packet asks for an A record matching want.
func parseMDNSQuestion(msg []byte, want string) (qname string, qid uint16, ok bool) {
	if len(msg) < 12 {
		return "", 0, false
	}
	qid = uint16(msg[0])<<8 | uint16(msg[1])
	flags := uint16(msg[2])<<8 | uint16(msg[3])
	if flags&0x8000 != 0 { // response, not a query
		return "", 0, false
	}
	qdcount := int(msg[4])<<8 | int(msg[5])
	if qdcount < 1 {
		return "", 0, false
	}

	// Parse first question name (labels) starting at offset 12.
	off := 12
	var labels []string
	for off < len(msg) {
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || off+l > len(msg) { // compression/garbage — bail
			return "", 0, false
		}
		labels = append(labels, strings.ToLower(string(msg[off:off+l])))
		off += l
	}
	if off+4 > len(msg) {
		return "", 0, false
	}
	qtype := uint16(msg[off])<<8 | uint16(msg[off+1])
	name := strings.Join(labels, ".")
	// A (1) or ANY (255) for our advertised name.
	if name == want && (qtype == 1 || qtype == 255) {
		return name, qid, true
	}
	return "", 0, false
}

// buildMDNSAnswer constructs an mDNS A-record response for name -> ip.
func buildMDNSAnswer(qid uint16, name string, ip net.IP) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	var b []byte
	put16 := func(v uint16) { b = append(b, byte(v>>8), byte(v)) }
	put32 := func(v uint32) { b = append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v)) }

	put16(qid)      // transaction id
	put16(0x8400)   // flags: response + authoritative
	put16(0)        // questions
	put16(1)        // answers
	put16(0)        // authority
	put16(0)        // additional

	// Answer name (labels)
	for _, lbl := range strings.Split(name, ".") {
		b = append(b, byte(len(lbl)))
		b = append(b, []byte(lbl)...)
	}
	b = append(b, 0)        // end of name
	put16(1)                // type A
	put16(0x8001)           // class IN + cache-flush bit
	put32(mdnsTTL)          // TTL
	put16(4)                // rdlength
	b = append(b, ip4...)   // rdata
	return b
}

// localDashboardURL returns the friendly URL to print at startup.
func localDashboardURL(hostName, port string) string {
	hostName = strings.TrimSuffix(strings.ToLower(hostName), ".")
	if hostName == "" {
		hostName = defaultLocalHost
	}
	return fmt.Sprintf("http://%s:%s", hostName, port)
}

var _ = log.Printf
