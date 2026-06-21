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
//	GET /probe/smtp?host=&port=-> SMTP banner
//
// All /probe/* endpoints require the X-Probe-Key header to equal $PROBE_KEY.
package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

var (
	stack       = env("PROBE_STACK", "unknown") // "ipv4" | "ipv6"
	probeKey    = os.Getenv("PROBE_KEY")
	allowOrigin = env("ALLOW_ORIGIN", "https://ipcow.com")
	listenAddr  = env("PROBE_ADDR", "127.0.0.1:8000")
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
	w.Header().Set("access-control-allow-origin", allowOrigin)
	writeJSON(w, http.StatusOK, map[string]any{"ip": clientIP(r), "stack": stack})
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
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

func cors(w http.ResponseWriter) {
	h := w.Header()
	h.Set("access-control-allow-origin", allowOrigin)
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
		OriginPatterns: []string{"ipcow.com", "*.ipcow.com", "localhost:*"},
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

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleEcho)
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/probe/dns", handleDNS)
	mux.HandleFunc("/probe/tcp", handleTCP)
	mux.HandleFunc("/probe/http", handleHTTP)
	mux.HandleFunc("/probe/ping", handlePing)
	mux.HandleFunc("/probe/smtp", handleSMTP)
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
