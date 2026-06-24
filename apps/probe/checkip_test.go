package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The checkip* hosts must reproduce the legacy plain-text contract exactly.
func TestHandleEchoCheckIP(t *testing.T) {
	cases := []struct {
		name, host, target, wantBody, wantCT string
	}{
		{"plain", "checkip.ipcow.com", "/", "1.2.3.4\n", "text/plain; charset=utf-8"},
		{"json", "checkip.ipcow.com", "/?json", "{\"ip\":\"1.2.3.4\"}\n", "application/json; charset=utf-8"},
		{"checkipv4 plain", "checkipv4.ipcow.com", "/", "1.2.3.4\n", "text/plain; charset=utf-8"},
		{"host with port", "checkip.ipcow.com:443", "/", "1.2.3.4\n", "text/plain; charset=utf-8"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, c.target, nil)
			r.Host = c.host
			r.Header.Set("x-forwarded-for", "1.2.3.4")
			w := httptest.NewRecorder()
			handleEcho(w, r)
			if got := w.Body.String(); got != c.wantBody {
				t.Errorf("body = %q, want %q", got, c.wantBody)
			}
			if got := w.Header().Get("content-type"); got != c.wantCT {
				t.Errorf("content-type = %q, want %q", got, c.wantCT)
			}
			if got := w.Header().Get("cache-control"); got != "no-store" {
				t.Errorf("cache-control = %q, want no-store", got)
			}
		})
	}
}

// checkipv6 reports only IPv6; a v4 caller gets the notice (the dual-stack edge case).
func TestHandleEchoCheckIPv6Notice(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "checkipv6.ipcow.com"
	r.Header.Set("x-forwarded-for", "1.2.3.4") // v4 caller
	w := httptest.NewRecorder()
	handleEcho(w, r)
	if got := strings.TrimSpace(w.Body.String()); got != "No IPv6 address detected" {
		t.Errorf("body = %q, want the no-v6 notice", got)
	}
}

func TestHandleEchoCheckIPv6(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "checkipv6.ipcow.com"
	r.Header.Set("x-forwarded-for", "2606:4700:4700::1111")
	w := httptest.NewRecorder()
	handleEcho(w, r)
	if got := strings.TrimSpace(w.Body.String()); got != "2606:4700:4700::1111" {
		t.Errorf("body = %q, want the v6 address", got)
	}
}

// The ipv4/ipv6 echo hosts keep the JSON {ip,stack} contract the hero depends on.
func TestHandleEchoJSON(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "ipv4.ipcow.com"
	r.Header.Set("x-forwarded-for", "1.2.3.4")
	w := httptest.NewRecorder()
	handleEcho(w, r)
	body := w.Body.String()
	if !strings.Contains(body, `"ip":"1.2.3.4"`) || !strings.Contains(body, `"stack"`) {
		t.Errorf("expected JSON echo with ip+stack, got %q", body)
	}
	if ct := w.Header().Get("content-type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
}
