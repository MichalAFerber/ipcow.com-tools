package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"
)

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func keyInfo(c *x509.Certificate) string {
	switch pk := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d-bit", pk.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", pk.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return c.PublicKeyAlgorithm.String()
	}
}

// handleSSL connects over this box's stack, completes a TLS handshake, and reports the
// presented certificate. Verification is disabled for the handshake so we can inspect even an
// invalid cert (expired, self-signed, wrong host); we then verify separately against the system
// roots and the requested name. The response is intentionally flat for ProbeRunner.
func handleSSL(w http.ResponseWriter, r *http.Request) {
	if !requireKey(w, r) {
		return
	}
	host := r.URL.Query().Get("host")
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing host"})
		return
	}
	port := r.URL.Query().Get("port")
	if port == "" {
		port = "443"
	}
	servername := r.URL.Query().Get("servername")
	if servername == "" {
		servername = host
	}
	start := time.Now()

	d := net.Dialer{Timeout: 8 * time.Second, Control: safeDialControl}
	raw, err := d.DialContext(r.Context(), tcpNetwork(), net.JoinHostPort(host, port))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "stack": stack, "host": host, "port": port, "error": "A socket error occurred — " + err.Error() + ". The host may be down or a firewall could be blocking the connection.", "elapsed_ms": sinceMS(start)})
		return
	}
	defer raw.Close()

	conn := tls.Client(raw, &tls.Config{ServerName: servername, InsecureSkipVerify: true})
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if err := conn.HandshakeContext(r.Context()); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "stack": stack, "host": host, "port": port, "error": "The TLS handshake failed — " + err.Error() + ".", "elapsed_ms": sinceMS(start)})
		return
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "stack": stack, "host": host, "port": port, "error": "the server presented no certificate", "elapsed_ms": sinceMS(start)})
		return
	}

	resp := map[string]any{
		"ok":          true,
		"stack":       stack,
		"host":        host,
		"port":        port,
		"servername":  servername,
		"tls_version": tlsVersionName(cs.Version),
		"cipher":      tls.CipherSuiteName(cs.CipherSuite),
		"elapsed_ms":  sinceMS(start),
	}
	for k, v := range certReport(cs.PeerCertificates, servername, time.Now()) {
		resp[k] = v
	}
	writeJSON(w, http.StatusOK, resp)
}

// certReport verifies the presented chain against the system roots and the requested name and
// describes the leaf certificate. Split out from handleSSL so it can be unit-tested without a
// live TLS connection.
func certReport(certs []*x509.Certificate, servername string, now time.Time) map[string]any {
	leaf := certs[0]
	intermediates := x509.NewCertPool()
	chain := make([]string, 0, len(certs)-1)
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
		chain = append(chain, c.Subject.CommonName)
	}
	_, verifyErr := leaf.Verify(x509.VerifyOptions{DNSName: servername, Intermediates: intermediates, CurrentTime: now})

	rep := map[string]any{
		"valid":               verifyErr == nil,
		"hostname_match":      leaf.VerifyHostname(servername) == nil,
		"expires_in_days":     int(leaf.NotAfter.Sub(now).Hours() / 24),
		"subject":             leaf.Subject.CommonName,
		"issuer":              leaf.Issuer.CommonName,
		"san":                 leaf.DNSNames,
		"not_before":          leaf.NotBefore.UTC().Format("2006-01-02"),
		"not_after":           leaf.NotAfter.UTC().Format("2006-01-02"),
		"serial":              leaf.SerialNumber.Text(16),
		"key":                 keyInfo(leaf),
		"signature_algorithm": leaf.SignatureAlgorithm.String(),
		"chain":               chain,
	}
	if verifyErr != nil {
		rep["validation_error"] = verifyErr.Error()
	}
	return rep
}
