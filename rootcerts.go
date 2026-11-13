// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package rootcerts

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const pemCertificateBlockType = "CERTIFICATE"

var (
	// maxCAPEMBytes bounds the size of a single PEM file loaded from disk
	// (CAFile, or each file encountered under CAPath).
	maxCAPEMBytes int64 = 1 << 20 // 1 MiB

	// maxCACertificates bounds the total number of certificates accepted
	// during a single load.
	maxCACertificates = 1024
)

// Config determines where LoadCACerts will load certificates from. When CAFile,
// CACertificate and CAPath are blank, this library's functions will either load
// system roots explicitly and return them, or set the CertPool to nil to allow
// Go's standard library to load system certs.
type Config struct {
	// CAFile is a path to a PEM-encoded certificate file or bundle. Takes
	// precedence over CACertificate and CAPath.
	CAFile string

	// CACertificate is a PEM-encoded certificate or bundle. Takes precedence
	// over CAPath.
	CACertificate []byte

	// CAPath is a path to a directory populated with PEM-encoded certificates.
	CAPath string

	// LegacyCompat restores the historical, lenient loading behavior: PEM
	// input is parsed with x509.CertPool.AppendCertsFromPEM, so malformed,
	// non-certificate, or trailing blocks are silently skipped, and no file
	// type, size, or certificate count limits are enforced. The default
	// strict behavior is atomic: any invalid input fails the entire load.
	LegacyCompat bool
}

// ConfigureTLS sets up the RootCAs on the provided tls.Config based on the
// Config specified.
func ConfigureTLS(t *tls.Config, c *Config) error {
	if t == nil {
		return nil
	}
	pool, err := LoadCACerts(c)
	if err != nil {
		return err
	}
	t.RootCAs = pool
	return nil
}

// LoadCACerts loads a CertPool based on the Config specified.
func LoadCACerts(c *Config) (*x509.CertPool, error) {
	if c == nil {
		c = &Config{}
	}
	if c.CAFile != "" {
		return loadCAFile(c.CAFile, c.LegacyCompat)
	}
	if len(c.CACertificate) != 0 {
		return appendCertificate(c.CACertificate, c.LegacyCompat)
	}
	if c.CAPath != "" {
		return loadCAPath(c.CAPath, c.LegacyCompat)
	}

	return LoadSystemCAs()
}

// LoadCAFile loads a single PEM-encoded file from the path specified. The
// load is strict and atomic: the file must be a regular file within the size
// limit, every PEM block must be a parseable X.509 certificate, and any
// trailing or truncated data fails the entire load.
func LoadCAFile(caFile string) (*x509.CertPool, error) {
	return loadCAFile(caFile, false)
}

func loadCAFile(caFile string, legacyCompat bool) (*x509.CertPool, error) {
	if legacyCompat {
		return loadCAFileLegacy(caFile)
	}

	info, err := os.Stat(caFile)
	if err != nil {
		return nil, fmt.Errorf("Error loading CA File: %s", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("Error loading CA File: %s is not a regular file", caFile)
	}
	if info.Size() > maxCAPEMBytes {
		return nil, fmt.Errorf("Error loading CA File: %s exceeds maximum size of %d bytes", caFile, maxCAPEMBytes)
	}

	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("Error loading CA File: %s", err)
	}

	pool := x509.NewCertPool()
	count := 0
	if err := appendCertsFromPEMStrict(pool, pemBytes, caFile, &count); err != nil {
		return nil, err
	}

	return pool, nil
}

func loadCAFileLegacy(caFile string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("Error loading CA File: %s", err)
	}

	ok := pool.AppendCertsFromPEM(pem)
	if !ok {
		return nil, fmt.Errorf("Error loading CA File: Couldn't parse PEM in: %s", caFile)
	}

	return pool, nil
}

// AppendCertificate appends an in-memory PEM-encoded certificate or bundle
// and returns a pool. The load is strict and atomic: every PEM block must be
// a parseable X.509 certificate, and any trailing or truncated data fails
// the entire load.
func AppendCertificate(ca []byte) (*x509.CertPool, error) {
	return appendCertificate(ca, false)
}

func appendCertificate(ca []byte, legacyCompat bool) (*x509.CertPool, error) {
	if legacyCompat {
		return appendCertificateLegacy(ca)
	}

	pool := x509.NewCertPool()
	count := 0
	if err := appendCertsFromPEMStrict(pool, ca, "CACertificate", &count); err != nil {
		return nil, err
	}

	return pool, nil
}

func appendCertificateLegacy(ca []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	ok := pool.AppendCertsFromPEM(ca)
	if !ok {
		return nil, errors.New("Error appending CA: Couldn't parse PEM")
	}

	return pool, nil
}

// LoadCAPath walks the provided path and loads all certificates encountered
// into a pool. The load is strict and atomic: only regular files (or
// symlinks resolving to regular files) within the size limit are accepted,
// every PEM block must be a parseable X.509 certificate, and any invalid
// file fails the entire load.
func LoadCAPath(caPath string) (*x509.CertPool, error) {
	return loadCAPath(caPath, false)
}

func loadCAPath(caPath string, legacyCompat bool) (*x509.CertPool, error) {
	if legacyCompat {
		return loadCAPathLegacy(caPath)
	}

	pool := x509.NewCertPool()
	count := 0
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		size, err := regularFileSize(path, info)
		if err != nil {
			return err
		}
		if size > maxCAPEMBytes {
			return fmt.Errorf("Error loading CA Path: %s exceeds maximum size of %d bytes", path, maxCAPEMBytes)
		}

		pemBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("Error loading file from CAPath: %s", err)
		}

		if err := appendCertsFromPEMStrict(pool, pemBytes, path, &count); err != nil {
			return err
		}

		return nil
	}

	err := filepath.Walk(caPath, walkFn)
	if err != nil {
		return nil, err
	}

	return pool, nil
}

// regularFileSize returns the size of the file at path, requiring it to be
// a regular file or a symlink that resolves to a regular file.
func regularFileSize(path string, info os.FileInfo) (int64, error) {
	mode := info.Mode()
	if mode.IsRegular() {
		return info.Size(), nil
	}
	if mode&os.ModeSymlink == 0 {
		return 0, fmt.Errorf("Error loading CA Path: %s is not a regular file", path)
	}
	target, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("Error loading file from CAPath: %s", err)
	}
	if !target.Mode().IsRegular() {
		return 0, fmt.Errorf("Error loading CA Path: %s does not resolve to a regular file", path)
	}
	return target.Size(), nil
}

// appendCertsFromPEMStrict decodes pemBytes block by block, requiring every
// block to be a parseable X.509 certificate and rejecting any data before,
// between, or after PEM blocks. On the first failure it returns an error and
// the pool must be discarded by the caller, keeping the load atomic.
func appendCertsFromPEMStrict(pool *x509.CertPool, pemBytes []byte, source string, count *int) error {
	rest := bytes.TrimSpace(pemBytes)
	if len(rest) == 0 {
		return fmt.Errorf("Error loading CA certificates from %s: no PEM data", source)
	}

	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return fmt.Errorf("Error loading CA certificates from %s: unexpected data outside PEM block", source)
		}

		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return fmt.Errorf("Error loading CA certificates from %s: invalid or truncated PEM block", source)
		}
		if block.Type != pemCertificateBlockType {
			return fmt.Errorf("Error loading CA certificates from %s: unsupported PEM block type %q", source, block.Type)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("Error loading CA certificates from %s: %s", source, err)
		}
		if *count >= maxCACertificates {
			return fmt.Errorf("Error loading CA certificates from %s: exceeds maximum of %d certificates", source, maxCACertificates)
		}

		pool.AddCert(cert)
		*count++
		rest = bytes.TrimSpace(rest)
	}

	return nil
}

func loadCAPathLegacy(caPath string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		pem, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("Error loading file from CAPath: %s", err)
		}

		ok := pool.AppendCertsFromPEM(pem)
		if !ok {
			return fmt.Errorf("Error loading CA Path: Couldn't parse PEM in: %s", path)
		}

		return nil
	}

	err := filepath.Walk(caPath, walkFn)
	if err != nil {
		return nil, err
	}

	return pool, nil
}
