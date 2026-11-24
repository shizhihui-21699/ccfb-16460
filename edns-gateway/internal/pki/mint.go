// Package pki 实现企业内部 CA 加载与按 SNI 动态签发叶子证书。
//
// 透明导流（tproxy）场景下，客户端仍按原始解析器域名（如 dns.google）发起 TLS，
// 网关必须出示该域名的证书。方案：企业根 CA 通过组策略/MDM 下发到终端信任库，
// 网关用 CA 私钥按 ClientHello SNI 实时签发短期叶子证书并缓存。
// 私钥永不离开网关，叶子证书有效期短（24h），泄露面可控。
package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

// Mint 证书动态签发器。
type Mint struct {
	caCert    *x509.Certificate
	caKey     any
	leafCache sync.Map // SNI -> *tls.Certificate
}

// LoadCA 从 PEM 文件加载 CA 证书与私钥（支持 RSA/ECDSA）。
func LoadCA(certFile, keyFile string) (*Mint, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	ca, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA keypair: %w", err)
	}
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, err
	}
	caKey := ca.PrivateKey
	if !caCert.IsCA {
		return nil, errors.New("给定证书不是 CA（缺 BasicConstraints CA:TRUE）")
	}
	return &Mint{caCert: caCert, caKey: caKey}, nil
}

// TLSConfig 返回带 GetCertificate 回调的 TLS 配置，按 SNI 动态签发。
func (m *Mint) TLSConfig(nextProtos []string) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     nextProtos,
		GetCertificate: m.getCertificate,
	}
}

func (m *Mint) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if name == "" {
		name = "edge-dns.internal" // 无 SNI 时的兜底
	}
	if cached, ok := m.leafCache.Load(name); ok {
		return cached.(*tls.Certificate), nil
	}
	leaf, err := m.mintLeaf(name)
	if err != nil {
		return nil, err
	}
	m.leafCache.Store(name, leaf)
	return leaf, nil
}

func (m *Mint) mintLeaf(domain string) (*tls.Certificate, error) {
	// 叶子密钥每次签发新生成，避免跨连接密钥复用
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"Enterprise EDNS Gateway"},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, &priv.PublicKey, m.caKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, m.caCert.Raw},
		PrivateKey:  priv,
		Leaf:        tmpl,
	}, nil
}
