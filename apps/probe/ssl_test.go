package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func makeCert(t *testing.T, cn string, dnsNames []string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dnsNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCertReport(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := makeCert(t, "example.com", []string{"example.com"}, now.AddDate(0, 0, -1), now.AddDate(0, 0, 30))

	rep := certReport([]*x509.Certificate{leaf}, "example.com", now)
	// Self-signed -> not chain-valid, but the name matches and the math is right.
	if rep["valid"] != false {
		t.Errorf("valid = %v, want false (untrusted self-signed)", rep["valid"])
	}
	if rep["hostname_match"] != true {
		t.Errorf("hostname_match = %v, want true", rep["hostname_match"])
	}
	if rep["expires_in_days"] != 30 {
		t.Errorf("expires_in_days = %v, want 30", rep["expires_in_days"])
	}
	if rep["key"] != "ECDSA P-256" {
		t.Errorf("key = %v, want ECDSA P-256", rep["key"])
	}
	if rep["validation_error"] == nil {
		t.Error("validation_error should be set for an untrusted cert")
	}

	// Wrong host.
	if r := certReport([]*x509.Certificate{leaf}, "other.example.net", now); r["hostname_match"] != false {
		t.Errorf("hostname_match (wrong host) = %v, want false", r["hostname_match"])
	}

	// Expired -> negative days remaining.
	expired := makeCert(t, "old.example.com", []string{"old.example.com"}, now.AddDate(-1, 0, 0), now.AddDate(0, 0, -1))
	if days, _ := certReport([]*x509.Certificate{expired}, "old.example.com", now)["expires_in_days"].(int); days >= 0 {
		t.Errorf("expires_in_days (expired) = %d, want negative", days)
	}
}

func TestTLSVersionName(t *testing.T) {
	if got := tlsVersionName(0x0304); got != "TLS 1.3" {
		t.Errorf("tlsVersionName(TLS1.3) = %q", got)
	}
}
