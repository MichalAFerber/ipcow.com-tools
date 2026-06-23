// ipcow probe — a small per-stack network agent (Go, stdlib only).
//
// Two instances run, one per stack, each with public connectivity on only one family:
//
//	ipv4.ipcow.com -> tgwab-ipcow-ipv4   (PROBE_STACK=ipv4)
//	ipv6.ipcow.com -> tgwab-ipcow-ipv6   (PROBE_STACK=ipv6)
//
// Because each box only has public reachability over its own family, a probe run here is
// inherently a probe over that stack. The Astro /api/probe route fans a request out to
// both boxes and merges the results.
//
// Endpoints:
//
//	GET /                      -> IP echo: { ip, stack }      (public, CORS — the hero uses this)
//	GET /healthz               -> { ok, stack }
//	GET /probe/dns?host=       -> resolve A/AAAA for host
//	GET /probe/tcp?host=&port= -> TCP connect timing
//	GET /probe/http?url=       -> HTTP GET status + timing
//	GET /probe/ping?host=      -> ICMP ping (avg rtt)
//	GET /probe/traceroute?host=-> traceroute hops (numeric)
//	GET /probe/smtp?host=&port=-> SMTP banner
//	GET /probe/ssl?host=&port= -> TLS certificate details
//
// All /probe/* endpoints require the X-Probe-Key header to equal $PROBE_KEY.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

var (
	stack      = env("PROBE_STACK", "unknown") // "ipv4" | "ipv6"
	probeKey   = os.Getenv("PROBE_KEY")
	listenAddr = env("PROBE_ADDR", "127.0.0.1:8000")
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// tcpNetwork / ipNetwork pin operations to this box's stack.
func tcpNetwork() string {
	switch stack {
	case "ipv4":
		return "tcp4"
	case "ipv6":
		return "tcp6"
	default:
		return "tcp"
	}
}

func ipNetwork() string {
	switch stack {
	case "ipv4":
		return "ip4"
	case "ipv6":
		return "ip6"
	default:
		return "ip"
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("x-forwarded-for"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func requireKey(w http.ResponseWriter, r *http.Request) bool {
	if probeKey == "" || r.Header.Get("x-probe-key") != probeKey {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid or missing X-Probe-Key"})
		return false
	}
	return true
}

func sinceMS(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000.0
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

func handleEcho(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	cors(w)
	writeJSON(w, http.StatusOK, map[string]any{"ip": clientIP(r), "stack": stack})
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	cors(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stack": stack})
}

func handleDNS(w http.ResponseWriter, r *http.Request) {
	if !requireKey(w, r) {
		return
	}
	host := r.URL.Query().Get("host")
	start := time.Now()
	ips, err := net.DefaultResolver.LookupIP(r.Context(), ipNetwork(), host)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "stack": stack, "host": host, "error": "DNS resolution failed: " + err.Error(), "elapsed_ms": sinceMS(start)})
		return
	}
	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, ip.String())
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stack": stack, "host": host, "addresses": addrs, "elapsed_ms": sinceMS(start)})
}

func handleTCP(w http.ResponseWriter, r *http.Request) {
	if !requireKey(w, r) {
		return
	}
	host := r.URL.Query().Get("host")
	port := r.URL.Query().Get("port")
	start := time.Now()
	d := net.Dialer{Timeout: 6 * time.Second}
	conn, err := d.DialContext(r.Context(), tcpNetwork(), net.JoinHostPort(host, port))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "stack": stack, "host": host, "port": port, "error": "A socket error occurred — " + err.Error() + ". A firewall could be blocking the connection or the host may be down.", "elapsed_ms": sinceMS(start)})
		return
	}
	peer := conn.RemoteAddr().String()
	_ = conn.Close()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stack": stack, "host": host, "port": port, "peer": peer, "elapsed_ms": sinceMS(start)})
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !requireKey(w, r) {
		return
	}
	target := r.URL.Query().Get("url")
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "url must start with http:// or https://"})
		return
	}
	start := time.Now()
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, tcpNetwork(), addr)
		},
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	req.Header.Set("user-agent", "ipcow-probe/1.0")
	resp, err := client.Do(req)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "stack": stack, "url": target, "error": "A socket error occurred during the HTTP request — " + err.Error() + ".", "elapsed_ms": sinceMS(start)})
		return
	}
	defer resp.Body.Close()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stack": stack, "status": resp.StatusCode, "final_url": resp.Request.URL.String(), "server": resp.Header.Get("server"), "elapsed_ms": sinceMS(start)})
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	if !requireKey(w, r) {
		return
	}
	host := r.URL.Query().Get("host")
	flag := "-4"
	if stack == "ipv6" {
		flag = "-6"
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ping", flag, "-c", "3", "-w", "5", host).CombinedOutput()
	text := string(out)
	var avg string
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "min/avg/max") && strings.Contains(line, "=") {
			nums := strings.Split(strings.TrimSpace(strings.Split(line, "=")[1]), "/")
			if len(nums) > 1 {
				avg = nums[1]
			}
		}
	}
	resp := map[string]any{"ok": err == nil, "stack": stack, "host": host, "raw": tail(text, 400), "elapsed_ms": sinceMS(start)}
	if avg != "" {
		if f, e := strconv.ParseFloat(avg, 64); e == nil {
			resp["avg_rtt_ms"] = f
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

type traceHop struct {
	Hop     int     `json:"hop"`
	IP      string  `json:"ip,omitempty"`
	RTT     float64 `json:"rtt_ms,omitempty"`
	Timeout bool    `json:"timeout,omitempty"`
}

// parseHops turns GNU/BusyBox traceroute output into structured hops. Each data line starts
// with the hop number; "*" means the hop did not answer. We keep the first responding address
// and RTT per hop.
func parseHops(text string) []traceHop {
	var hops []traceHop
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		hop := traceHop{Hop: n}
		if fields[1] == "*" {
			hop.Timeout = true
		} else {
			hop.IP = fields[1]
			for i := 2; i < len(fields); i++ {
				if fields[i] == "ms" {
					if f, e := strconv.ParseFloat(fields[i-1], 64); e == nil {
						hop.RTT = f
						break
					}
				}
			}
		}
		hops = append(hops, hop)
	}
	return hops
}

// handleTraceroute traces the network path to a host over this box's stack. traceroute's exit
// code is unreliable (non-zero on a partial trace), so success is "we parsed at least one hop".
// The timeout stays under the Astro /api/probe fetch timeout (12s) so the caller sees a result.
func handleTraceroute(w http.ResponseWriter, r *http.Request) {
	if !requireKey(w, r) {
		return
	}
	host := r.URL.Query().Get("host")
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing host"})
		return
	}
	flag := "-4"
	if stack == "ipv6" {
		flag = "-6"
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 11*time.Second)
	defer cancel()
	// -n numeric (skip rDNS), -q 1 one probe per hop, -w 2 wait 2s, -m 20 max hops.
	out, _ := exec.CommandContext(ctx, "traceroute", flag, "-n", "-q", "1", "-w", "2", "-m", "20", host).CombinedOutput()
	text := string(out)
	hops := parseHops(text)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         len(hops) > 0,
		"stack":      stack,
		"host":       host,
		"hops":       hops,
		"raw":        tail(text, 2000),
		"elapsed_ms": sinceMS(start),
	})
}

func handleSMTP(w http.ResponseWriter, r *http.Request) {
	if !requireKey(w, r) {
		return
	}
	host := r.URL.Query().Get("host")
	port := r.URL.Query().Get("port")
	if port == "" {
		port = "25"
	}
	start := time.Now()
	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(r.Context(), tcpNetwork(), net.JoinHostPort(host, port))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "stack": stack, "host": host, "port": port, "error": "A socket error occurred during the SMTP probe — " + err.Error() + ". Port 25 is often blocked on consumer and cloud networks.", "elapsed_ms": sinceMS(start)})
		return
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(6 * time.Second))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	banner := strings.TrimSpace(string(buf[:n]))
	_, _ = conn.Write([]byte("QUIT\r\n"))
	writeJSON(w, http.StatusOK, map[string]any{"ok": strings.HasPrefix(banner, "220"), "stack": stack, "host": host, "port": port, "banner": banner, "elapsed_ms": sinceMS(start)})
}

// Public, credential-less endpoints (IP echo, healthz, speedtest) allow any origin so the
// hero/tools work from the apex, www, the workers.dev preview, and the staging host alike.
func cors(w http.ResponseWriter) {
	h := w.Header()
	h.Set("access-control-allow-origin", "*")
	h.Set("access-control-allow-methods", "GET, POST, OPTIONS")
	h.Set("access-control-allow-headers", "content-type")
}

const (
	maxSpeedBytes     = 200 << 20 // 200 MiB hard cap
	defaultSpeedBytes = 25 << 20  // 25 MiB
)

// handleSpeedDownload streams up to maxSpeedBytes of zeros for a download throughput test.
func handleSpeedDownload(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
	if n <= 0 || n > maxSpeedBytes {
		n = defaultSpeedBytes
	}
	h := w.Header()
	h.Set("content-type", "application/octet-stream")
	h.Set("cache-control", "no-store")
	h.Set("content-length", strconv.Itoa(n))
	buf := make([]byte, 64<<10)
	for remaining := n; remaining > 0; {
		chunk := len(buf)
		if remaining < chunk {
			chunk = remaining
		}
		if _, err := w.Write(buf[:chunk]); err != nil {
			return
		}
		remaining -= chunk
	}
}

// handleSpeedUpload discards the request body and reports bytes/timing for an upload test.
func handleSpeedUpload(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	start := time.Now()
	n, _ := io.Copy(io.Discard, io.LimitReader(r.Body, maxSpeedBytes))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stack": stack, "bytes": n, "elapsed_ms": sinceMS(start)})
}

// handleWS is a WebSocket echo for the connectivity test — detects proxies/firewalls that
// break WebSocket upgrades.
func handleWS(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// workers.dev subdomains are per-account, so scope the wildcard to ours
		// (*.techguywithabeard.workers.dev covers the preview + version URLs) rather
		// than *.workers.dev, which would let any account's Worker open a socket.
		OriginPatterns: []string{"ipcow.com", "*.ipcow.com", "*.techguywithabeard.workers.dev", "localhost:*"},
	})
	if err != nil {
		return
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	for {
		rctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		typ, data, err := c.Read(rctx)
		cancel()
		if err != nil {
			return
		}
		wctx, cancel2 := context.WithTimeout(r.Context(), 10*time.Second)
		err = c.Write(wctx, typ, data)
		cancel2()
		if err != nil {
			return
		}
	}
}

// Default DNSBLs (RBLs) checked by /probe/dnsbl. Override with DNSBL_ZONES (comma-separated).
// For accurate results the box should resolve via a local recursive resolver (e.g. unbound):
// many lists refuse queries that arrive via large public resolvers.
var dnsblZones = loadZones()

func loadZones() []string {
	if v := os.Getenv("DNSBL_ZONES"); strings.TrimSpace(v) != "" {
		var out []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return []string{
		"zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org",
		"dnsbl.sorbs.net", "spam.dnsbl.sorbs.net", "psbl.surriel.com",
		"cbl.abuseat.org", "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net",
		"dnsbl-3.uceprotect.net", "ix.dnsbl.manitu.net", "db.wpbl.info",
		"bl.mailspike.net", "dnsbl.dronebl.org", "all.s5h.net",
		"truncate.gbudb.net", "bl.0spam.org", "spamrbl.imp.ch",
	}
}

func reverseIPv4(ip net.IP) string {
	b := ip.To4()
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
}

func reverseIPv6(ip net.IP) string {
	b := ip.To16()
	var sb strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		fmt.Fprintf(&sb, "%x.%x.", b[i]&0x0f, b[i]>>4)
	}
	return strings.TrimSuffix(sb.String(), ".")
}

func dnsNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

type dnsblResult struct {
	Zone   string   `json:"zone"`
	Listed bool     `json:"listed"`
	Codes  []string `json:"codes,omitempty"`
	Error  string   `json:"error,omitempty"`
}

// handleDNSBL checks an IP against a set of DNS blacklists — the "blacklist sweep".
func handleDNSBL(w http.ResponseWriter, r *http.Request) {
	if !requireKey(w, r) {
		return
	}
	ipStr := r.URL.Query().Get("ip")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid or missing ip"})
		return
	}
	rev := reverseIPv6(ip)
	if v4 := ip.To4(); v4 != nil {
		rev = reverseIPv4(ip)
	}

	start := time.Now()
	zones := dnsblZones
	results := make([]dnsblResult, len(zones))
	sem := make(chan struct{}, 40)
	var wg sync.WaitGroup
	for i, zone := range zones {
		wg.Add(1)
		go func(i int, zone string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
			defer cancel()
			addrs, err := net.DefaultResolver.LookupHost(ctx, rev+"."+zone)
			res := dnsblResult{Zone: zone}
			switch {
			case err == nil && len(addrs) > 0:
				res.Listed = true
				res.Codes = addrs
			case err != nil && !dnsNotFound(err):
				res.Error = err.Error()
			}
			results[i] = res
		}(i, zone)
	}
	wg.Wait()

	listed := 0
	for _, res := range results {
		if res.Listed {
			listed++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "stack": stack, "ip": ipStr,
		"listed_count": listed, "total": len(zones),
		"listings": results, "elapsed_ms": sinceMS(start),
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleEcho)
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/probe/dns", handleDNS)
	mux.HandleFunc("/probe/tcp", handleTCP)
	mux.HandleFunc("/probe/http", handleHTTP)
	mux.HandleFunc("/probe/ping", handlePing)
	mux.HandleFunc("/probe/traceroute", handleTraceroute)
	mux.HandleFunc("/probe/smtp", handleSMTP)
	mux.HandleFunc("/probe/ssl", handleSSL)
	mux.HandleFunc("/probe/dnsbl", handleDNSBL)
	mux.HandleFunc("/speedtest/download", handleSpeedDownload)
	mux.HandleFunc("/speedtest/upload", handleSpeedUpload)
	mux.HandleFunc("/ws", handleWS)

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 20 * time.Second,
	}
	log.Printf("ipcow probe (%s) listening on %s", stack, listenAddr)
	log.Fatal(srv.ListenAndServe())
}
