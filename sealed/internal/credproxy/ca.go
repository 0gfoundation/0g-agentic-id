package credproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"
)

// CA is the per-boot root the proxy uses to terminate TLS for hosts an entry
// names. Its private key exists only in this process's memory; a new one is
// made at every boot, so a certificate copied out of one boot is worthless at
// the next.
type CA struct {
	cert    *x509.Certificate
	certDER []byte
	key     *ecdsa.PrivateKey

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
	now   func() time.Time
}

const (
	caLifetime   = 365 * 24 * time.Hour
	leafLifetime = 7 * 24 * time.Hour
	leafRenew    = 24 * time.Hour
)

// NewCA generates a fresh root.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "AgentDNA sealed credential proxy"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, certDER: der, key: key, leafs: map[string]*tls.Certificate{}, now: time.Now}, nil
}

// CertPEM is the root certificate, for the trust stores of the tools the
// harness runs.
func (ca *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.certDER})
}

// Pool is a cert pool holding only this root (tests use it as a client).
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

// Bundle is systemRoots (the image's PEM trust store) followed by this
// root. Tools whose CA variable replaces their trust store (SSL_CERT_FILE and
// the like) need the bundle so ordinary hosts still verify; NODE_EXTRA_CA_CERTS
// appends, so it gets the root alone (CertPEM). Writing both files is the
// caller's job, through privsep.
func (ca *CA) Bundle(systemRoots []byte) []byte {
	out := append([]byte{}, systemRoots...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(out, ca.CertPEM()...)
}

// leaf returns a certificate for host, issuing (and caching) one on first use
// and again when the cached one nears expiry.
func (ca *CA) leaf(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	now := ca.now()
	if c, ok := ca.leafs[host]; ok && now.Add(leafRenew).Before(c.Leaf.NotAfter) {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, ca.certDER}, PrivateKey: key, Leaf: parsed}
	ca.leafs[host] = c
	return c, nil
}

func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err) // crypto/rand failing leaves nothing safe to do
	}
	return n
}
