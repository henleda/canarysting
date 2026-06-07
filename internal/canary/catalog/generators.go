// The five canary generators. Each is a pure function of an injected rng
// (no I/O, no SDK call, no read of any real secret source — it cannot read a real
// secret, so it cannot emit one) that produces a realistic-looking but provably
// non-functional decoy, plus the per-type harmlessness predicate that proves it.
// Realism lives in the ENVELOPE (AKIA prefix, PEM armor, S3 listing shape);
// harmlessness lives in the CONTENTS (reserved/EXAMPLE namespaces + structural
// invalidity). See docs/CANARY.md and harmless.go.
package catalog

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/canarysting/canarysting/internal/contract"
	"github.com/canarysting/canarysting/internal/harmless"
)

// rng is the minimal entropy interface the generators need. It is satisfied by
// *lockedRand, so generation is safe under concurrent Catalog.Generate calls.
type rng interface {
	Intn(int) int
	Int63n(int64) int64
	Read([]byte) (int, error)
}

// Stable canary type identifiers. NEVER change once shipped: they key the
// engine's learned per-scope weights (internal/engine/calibration).
const (
	TypePlantedCredential contract.CanaryType = "planted_credential"
	TypeFakeSecret        contract.CanaryType = "fake_secret"
	TypeDecoyFile         contract.CanaryType = "decoy_file"
	TypeFakeBucket        contract.CanaryType = "fake_bucket"
	TypeFakeEndpoint      contract.CanaryType = "fake_endpoint"
)

const (
	base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	keyIDAlphabet  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	secretAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+"
)

func pick(r rng, alphabet string, n int) string {
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < n; i++ {
		b.WriteByte(alphabet[r.Intn(len(alphabet))])
	}
	return b.String()
}

// marker returns a fresh non-secret correlation marker (CSTING-CANARY-<token>).
func marker(r rng) string { return canaryMarker + pick(r, base32Alphabet, 12) }

// exampleAWSKeyID returns "AKIA" + 9 random + "EXAMPLE" (20 chars), an access key
// id in the AWS documentation EXAMPLE namespace (authenticates to nothing).
func exampleAWSKeyID(r rng) string { return "AKIA" + pick(r, keyIDAlphabet, 9) + "EXAMPLE" }

// exampleAWSSecret returns 30 random + "EXAMPLEKEY" (40 chars), an AWS-shaped
// secret in the EXAMPLE namespace.
func exampleAWSSecret(r rng) string { return pick(r, secretAlphabet, 30) + "EXAMPLEKEY" }

// reservedHost returns a plausible internal hostname in an RFC 2606 reserved
// domain (routes nowhere).
func reservedHost(r rng) string {
	names := []string{"db.payments", "vault.internal", "api.internal", "admin.corp", "secrets.svc"}
	tlds := []string{".example", ".invalid", ".test"}
	return names[r.Intn(len(names))] + tlds[r.Intn(len(tlds))]
}

// --- 1. planted credential (highest intent) ---

func genPlantedCredential(r rng) (Instance, error) {
	id, secret := exampleAWSKeyID(r), exampleAWSSecret(r)
	payload := fmt.Sprintf("# %s\n[default]\naws_access_key_id = %s\naws_secret_access_key = %s\nregion = us-east-1\n",
		marker(r), id, secret)
	return Instance{Type: TypePlantedCredential, Payload: []byte(payload)}, nil
}

func plantedCredentialHarmless(i Instance) error {
	ids := harmless.FindAWSKeyIDs(i.Payload)
	if len(ids) == 0 {
		return &harmless.Error{Reason: "planted_credential: no AWS key id present"}
	}
	for _, id := range ids {
		if !harmless.IsExampleAWSKeyID(id) {
			return &harmless.Error{Reason: "planted_credential: key id outside EXAMPLE namespace"}
		}
	}
	if !harmless.HasExampleAWSSecret(i.Payload) {
		return &harmless.Error{Reason: "planted_credential: no EXAMPLE secret present"}
	}
	if !carriesCanaryMarker(i.Payload) {
		return &harmless.Error{Reason: "planted_credential: missing marker"}
	}
	return nil
}

// --- 2. fake secret (PEM inert key or unsigned JWT) ---

func genFakeSecret(r rng) (Instance, error) {
	if r.Intn(2) == 0 {
		return Instance{Type: TypeFakeSecret, Payload: inertPEM(r)}, nil
	}
	// Wrap the bare JWT with a plaintext marker comment (the marker would be
	// base64-buried inside the token otherwise).
	jwt := unsignedJWT(r)
	payload := "# vault token (decoy)\n# " + marker(r) + "\n" + string(jwt) + "\n"
	return Instance{Type: TypeFakeSecret, Payload: []byte(payload)}, nil
}

// inertPEM produces a PEM "RSA PRIVATE KEY" block whose body cannot be valid DER:
// it begins with bytes that are not a DER SEQUENCE header (0x30), so every key
// parser fails. A trailing comment carries the marker.
func inertPEM(r rng) []byte {
	body := make([]byte, 256)
	r.Read(body)
	body[0], body[1] = 0x00, 0x00 // not a DER SEQUENCE: guarantees parse failure
	enc := base64.StdEncoding.EncodeToString(body)
	var b strings.Builder
	b.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
	for len(enc) > 0 {
		n := 64
		if n > len(enc) {
			n = len(enc)
		}
		b.WriteString(enc[:n] + "\n")
		enc = enc[n:]
	}
	b.WriteString("-----END RSA PRIVATE KEY-----\n")
	b.WriteString("# " + marker(r) + "\n")
	return []byte(b.String())
}

func unsignedJWT(r rng) []byte {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims := fmt.Sprintf(`{"iss":"https://auth.internal.example","aud":"payments.example","sub":"svc-decoy","exp":4102444800,"jti":"%s"}`, pick(r, base32Alphabet, 16))
	body := base64.RawURLEncoding.EncodeToString([]byte(claims))
	return []byte(header + "." + body + ".") // empty signature segment
}

var jwtRe = regexp.MustCompile(`[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.`)

func fakeSecretHarmless(i Instance) error {
	switch {
	case harmless.IsInertPrivateKey(i.Payload): // pem.Decode finds the block despite comments
		// ok
	case harmless.IsUnsignedJWT(jwtRe.FindString(string(i.Payload))):
		// ok
	default:
		return &harmless.Error{Reason: "fake_secret: neither an inert private key nor an unsigned JWT"}
	}
	if !carriesCanaryMarker(i.Payload) {
		return &harmless.Error{Reason: "fake_secret: missing marker"}
	}
	return nil
}

// --- 3. decoy file (.env honeyfile) ---

func genDecoyFile(r rng) (Instance, error) {
	payload := fmt.Sprintf("# %s\nAWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nDATABASE_URL=postgres://svc:decoy@%s:5432/payments\nJWT_SECRET=%s\n",
		marker(r), exampleAWSKeyID(r), exampleAWSSecret(r), reservedHost(r), pick(r, secretAlphabet, 24))
	return Instance{Type: TypeDecoyFile, Payload: []byte(payload)}, nil
}

func decoyFileHarmless(i Instance) error {
	// AWS keys and PEM blocks are validated by the universal harmless.CrossScan;
	// here we assert every embedded host is reserved and the marker is present.
	if err := harmless.AllHostsReserved(i.Payload); err != nil {
		return err
	}
	if !carriesCanaryMarker(i.Payload) {
		return &harmless.Error{Reason: "decoy_file: missing marker"}
	}
	return nil
}

// --- 4. fake bucket listing (S3 ListBucketResult) ---

func genFakeBucket(r rng) (Instance, error) {
	host := "s3.us-east-1.example"
	keys := []string{"payroll-exports/2026/q1.csv", "db-dumps/payments.sql.gz", "backups/vault-unseal.txt"}
	var objs strings.Builder
	for _, k := range keys {
		objs.WriteString(fmt.Sprintf(
			"  <Contents><Key>%s</Key><LastModified>2026-05-01T00:00:00.000Z</LastModified><Size>%d</Size><StorageClass>STANDARD</StorageClass></Contents>\n",
			k, 1024+r.Intn(1<<20)))
	}
	// No xmlns/real-host reference: the listing must point at no routable asset.
	payload := fmt.Sprintf(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- %s -->\n<ListBucketResult>\n  <Name>prod-db-backups</Name>\n  <Owner><ID>000000000000</ID></Owner>\n  <Endpoint>https://%s/prod-db-backups</Endpoint>\n%s</ListBucketResult>\n",
		marker(r), host, objs.String())
	return Instance{Type: TypeFakeBucket, Payload: []byte(payload)}, nil
}

func fakeBucketHarmless(i Instance) error {
	s := string(i.Payload)
	if !strings.Contains(s, "<ID>000000000000</ID>") {
		return &harmless.Error{Reason: "fake_bucket: owner id is not the reserved 000000000000"}
	}
	if strings.Contains(s, "X-Amz-Signature") {
		return &harmless.Error{Reason: "fake_bucket: listing carries a presigned URL signature"}
	}
	if err := harmless.AllHostsReserved(i.Payload); err != nil {
		return err
	}
	if !carriesCanaryMarker(i.Payload) {
		return &harmless.Error{Reason: "fake_bucket: missing marker"}
	}
	return nil
}

// --- 5. fake internal endpoint (lowest intent) ---

func genFakeEndpoint(r rng) (Instance, error) {
	hosts := []string{"admin.internal.example", "metrics.corp.test", "203.0.113.10:8443", "[2001:db8::1]:8443"}
	host := hosts[r.Intn(len(hosts))]
	payload := fmt.Sprintf("# service discovery (decoy)\nendpoint: https://%s/v1/admin\nrole: internal-admin\n# %s\n",
		host, marker(r))
	return Instance{Type: TypeFakeEndpoint, Payload: []byte(payload)}, nil
}

func fakeEndpointHarmless(i Instance) error {
	if err := harmless.AllHostsReserved(i.Payload); err != nil {
		return err
	}
	if !carriesCanaryMarker(i.Payload) {
		return &harmless.Error{Reason: "fake_endpoint: missing marker"}
	}
	return nil
}
