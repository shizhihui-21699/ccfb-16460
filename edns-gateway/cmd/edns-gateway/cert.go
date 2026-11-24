package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// runCert 生成企业根 CA（自签名）与一张演示叶子证书。
//
// 生产环境建议：
//   - 根 CA 离线保管，网关只持有中间 CA
//   - 通过 AD 组策略 / MDM 把根 CA 下发到终端受信任根存储
//   - 叶子证书由 pki.Mint 在运行时按 SNI 动态签发，无需预生成
func runCert(args []string) error {
	fs := flag.NewFlagSet("cert", flag.ContinueOnError)
	outDir := fs.String("out", "certs", "输出目录")
	org := fs.String("org", "Enterprise EDNS Gateway", "证书组织名")
	days := fs.Int("days", 3650, "CA 有效期天数")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		return err
	}

	// ---- 根 CA ----
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Enterprise EDNS Root CA",
			Organization: []string{*org},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, *days),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(*outDir, "ca.crt"), "CERTIFICATE", caDER); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(*outDir, "ca.key"), "RSA PRIVATE KEY",
		x509.MarshalPKCS1PrivateKey(caKey)); err != nil {
		return err
	}

	// ---- 演示叶子（固定 SNI，供无法动态签发的场景使用）----
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caCert, _ := x509.ParseCertificate(caDER)
	leafTmpl := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject: pkix.Name{
			CommonName:   "edge-dns.internal",
			Organization: []string{*org},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().AddDate(0, 0, 90),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"edge-dns.internal", "dns.google", "cloudflare-dns.com", "one.one.one.one"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(*outDir, "edge.crt"), "CERTIFICATE", leafDER); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(*outDir, "edge.key"), "RSA PRIVATE KEY",
		x509.MarshalPKCS1PrivateKey(leafKey)); err != nil {
		return err
	}

	println("已生成:")
	println("  " + filepath.Join(*outDir, "ca.crt") + "  企业根 CA（下发到终端信任库）")
	println("  " + filepath.Join(*outDir, "ca.key") + "  CA 私钥（严格保密，建议离线存放）")
	println("  " + filepath.Join(*outDir, "edge.crt") + " 演示叶子证书")
	println("  " + filepath.Join(*outDir, "edge.key") + " 演示叶子私钥")
	return nil
}

func writePEM(path, typ string, der []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}
