// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package rootcerts

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func validCAPEM(t *testing.T) []byte {
	t.Helper()
	pemBytes, err := os.ReadFile(testFixture("cafile", "cacert.pem"))
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return pemBytes
}

func writeCAFile(t *testing.T, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cacert.pem")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("err: %s", err)
	}
	return path
}

func pemBlock(blockType string, payload []byte) []byte {
	body := base64.StdEncoding.EncodeToString(payload)
	return []byte("-----BEGIN " + blockType + "-----\n" + body + "\n-----END " + blockType + "-----\n")
}

func expectLoadCAFileError(t *testing.T, contents []byte) {
	t.Helper()
	path := writeCAFile(t, contents)
	pool, err := LoadCACerts(&Config{CAFile: path})
	if err == nil {
		t.Fatal("expected error, got none")
	}
	if pool != nil {
		t.Fatal("expected nil pool on failed load")
	}
}

func TestLoadCACertsRejectsTrailingGarbage(t *testing.T) {
	pemBytes := append(validCAPEM(t), []byte("this is not pem\n")...)
	expectLoadCAFileError(t, pemBytes)
}

func TestLoadCACertsRejectsLeadingGarbage(t *testing.T) {
	pemBytes := append([]byte("garbage\n"), validCAPEM(t)...)
	expectLoadCAFileError(t, pemBytes)
}

func TestLoadCACertsRejectsNonCertificateBlock(t *testing.T) {
	pemBytes := append(validCAPEM(t), pemBlock("PRIVATE KEY", []byte("not a key"))...)
	expectLoadCAFileError(t, pemBytes)
}

func TestLoadCACertsRejectsBadCertificateDER(t *testing.T) {
	pemBytes := append(validCAPEM(t), pemBlock("CERTIFICATE", []byte("not a certificate"))...)
	expectLoadCAFileError(t, pemBytes)
}

func TestLoadCACertsRejectsTruncatedBlock(t *testing.T) {
	pemBytes := append(validCAPEM(t), []byte("-----BEGIN CERTIFICATE-----\nAAAA\n")...)
	expectLoadCAFileError(t, pemBytes)
}

func TestLoadCACertsRejectsEmptyFile(t *testing.T) {
	expectLoadCAFileError(t, []byte("   \n"))
}

func TestLoadCACertsRejectsTooManyCertificates(t *testing.T) {
	defer func(limit int) { maxCACertificates = limit }(maxCACertificates)
	maxCACertificates = 1

	valid := validCAPEM(t)
	pemBytes := append(valid, valid...)
	expectLoadCAFileError(t, pemBytes)
}

func TestLoadCACertsInMemRejectsTrailingGarbage(t *testing.T) {
	pemBytes := append(validCAPEM(t), []byte("junk")...)
	pool, err := LoadCACerts(&Config{CACertificate: pemBytes})
	if err == nil {
		t.Fatal("expected error, got none")
	}
	if pool != nil {
		t.Fatal("expected nil pool on failed load")
	}
}

func TestLoadCACertsLegacyCompatFromFile(t *testing.T) {
	pemBytes := append(validCAPEM(t), []byte("trailing junk\n")...)
	path := writeCAFile(t, pemBytes)
	p, err := LoadCACerts(&Config{CAFile: path, LegacyCompat: true})
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	testCertLoaded(t, p)
}

func TestLoadCACertsLegacyCompatInMem(t *testing.T) {
	pemBytes := append(validCAPEM(t), pemBlock("PRIVATE KEY", []byte("not a key"))...)
	p, err := LoadCACerts(&Config{CACertificate: pemBytes, LegacyCompat: true})
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	testCertLoaded(t, p)
}

func TestLoadCAPathRejectsOversizedFile(t *testing.T) {
	defer func(limit int64) { maxCAPEMBytes = limit }(maxCAPEMBytes)
	maxCAPEMBytes = 64

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cacert.pem"), validCAPEM(t), 0o600); err != nil {
		t.Fatalf("err: %s", err)
	}
	pool, err := LoadCACerts(&Config{CAPath: dir})
	if err == nil {
		t.Fatal("expected error, got none")
	}
	if pool != nil {
		t.Fatal("expected nil pool on failed load")
	}
}

func TestLoadCAPathRejectsSpecialFile(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "cacert.pem"), 0o600); err != nil {
		t.Fatalf("err: %s", err)
	}
	pool, err := LoadCACerts(&Config{CAPath: dir})
	if err == nil {
		t.Fatal("expected error, got none")
	}
	if pool != nil {
		t.Fatal("expected nil pool on failed load")
	}
}

func TestLoadCAPathRejectsBadBlockInOneFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.pem"), validCAPEM(t), 0o600); err != nil {
		t.Fatalf("err: %s", err)
	}
	bad := append(validCAPEM(t), []byte("garbage\n")...)
	if err := os.WriteFile(filepath.Join(dir, "bad.pem"), bad, 0o600); err != nil {
		t.Fatalf("err: %s", err)
	}
	pool, err := LoadCACerts(&Config{CAPath: dir})
	if err == nil {
		t.Fatal("expected error, got none")
	}
	if pool != nil {
		t.Fatal("expected nil pool on failed load")
	}
}

func TestLoadCAFileRejectsDirectory(t *testing.T) {
	pool, err := LoadCACerts(&Config{CAFile: t.TempDir()})
	if err == nil {
		t.Fatal("expected error, got none")
	}
	if pool != nil {
		t.Fatal("expected nil pool on failed load")
	}
}
