package harmless

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func TestInertPrivateKeyRejectsRealKey(t *testing.T) {
	// A genuine RSA key, PEM-armored, MUST fail IsInertPrivateKey (it parses). A
	// real key parses, so a real key definitionally cannot pass the predicate.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	realPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if IsInertPrivateKey(realPEM) {
		t.Fatal("a real RSA key passed IsInertPrivateKey — the predicate has no teeth")
	}
	// And CrossScan must reject it.
	if err := CrossScan(realPEM); err == nil {
		t.Fatal("CrossScan accepted a real RSA key")
	}
}

func TestInertPrivateKeyRejectsEncryptedAndOpenSSH(t *testing.T) {
	// An ENCRYPTED key is a real, passphrase-recoverable key — never "inert".
	encrypted := []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFDjBABg" +
		"kqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQI\n-----END ENCRYPTED PRIVATE KEY-----\n")
	if IsInertPrivateKey(encrypted) {
		t.Fatal("an ENCRYPTED private key was called inert")
	}
	// A legacy DEK-Info encrypted PEM is likewise real.
	legacy := []byte("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,XYZ\n\nZmlsbGVy\n-----END RSA PRIVATE KEY-----\n")
	if IsInertPrivateKey(legacy) {
		t.Fatal("a legacy DEK-Info encrypted key was called inert")
	}
	// An OpenSSH-format key cannot be parse-checked by the DER parsers; the
	// conservative predicate must NOT call it inert.
	openssh := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
	if IsInertPrivateKey(openssh) {
		t.Fatal("an OPENSSH PRIVATE KEY (unparseable label) was called inert")
	}
	// An inert PEM (non-DER body) is correctly inert.
	inert := []byte("-----BEGIN RSA PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAA\n-----END RSA PRIVATE KEY-----\n")
	if !IsInertPrivateKey(inert) {
		t.Fatal("an inert (non-DER) PEM body was not recognized as inert")
	}
}

func TestExampleAWSKeyIDHasTeeth(t *testing.T) {
	if !IsExampleAWSKeyID("AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("AWS-documented EXAMPLE key id was rejected")
	}
	if IsExampleAWSKeyID("AKIA1234567890ABCDEF") { // live-shaped, not EXAMPLE
		t.Fatal("a live-shaped AKIA id outside the EXAMPLE namespace was accepted")
	}
	if !HasExampleAWSSecret([]byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")) {
		t.Fatal("AWS-documented EXAMPLE secret was rejected")
	}
	if HasExampleAWSSecret([]byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYwJalrXUtnF")) { // 40 chars, not EXAMPLE
		t.Fatal("a non-EXAMPLE 40-char secret was accepted")
	}
}

func TestUnsignedJWTPredicate(t *testing.T) {
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`))
	if !IsUnsignedJWT(none + "." + claims + ".") {
		t.Fatal("a valid unsigned (alg:none, empty sig) JWT was rejected")
	}
	signed := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	if IsUnsignedJWT(signed + "." + claims + ".sig") {
		t.Fatal("a signed JWT (alg:HS256, non-empty sig) was accepted")
	}
}

func TestAllHostsReservedHasTeeth(t *testing.T) {
	// Reject arms (the predicate must have teeth on every host form).
	for _, bad := range []string{
		"endpoint: https://8.8.8.8/admin\n",                    // routable IPv4
		"endpoint: https://[2606:4700:4700::1111]:8443/x\n",    // routable IPv6 (guards the IPv6 branch)
		"endpoint: https://example.evil.com/x\n",               // reserved-SLD lookalike
		"endpoint: ssh://root@198.51.100.9.attacker.net:22/\n", // non-https scheme + suffix trick
	} {
		if err := AllHostsReserved([]byte(bad)); err == nil {
			t.Fatalf("a routable host was accepted: %q", bad)
		}
	}
	// Accept arms (reserved namespaces).
	for _, ok := range []string{"https://admin.internal.example/x", "https://192.0.2.5:8443/x", "https://[2001:db8::1]:8443/x"} {
		if err := AllHostsReserved([]byte(ok)); err != nil {
			t.Fatalf("reserved host %q was rejected: %v", ok, err)
		}
	}
}

func TestCrossScanIsUniversalBackstop(t *testing.T) {
	inertPEM := "-----BEGIN RSA PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAA\n-----END RSA PRIVATE KEY-----\n"
	for name, payload := range map[string]string{
		"live-aws-key":  inertPEM + "extra = AKIA1234567890ABCDEF\n",
		"routable-host": inertPEM + "# beacon https://attacker.evil.com/track\n",
	} {
		if err := CrossScan([]byte(payload)); err == nil {
			t.Fatalf("%s: CrossScan failed to reject a smuggled live secret/host", name)
		}
	}
	// A wholly reserved/inert payload passes.
	if err := CrossScan([]byte(inertPEM + "host = https://api.internal.example/v1\n")); err != nil {
		t.Fatalf("CrossScan rejected a provably-harmless payload: %v", err)
	}
}
