package config

import (
	"maps"
	"os"
	"path/filepath"
	"testing"
)

func writeEnv(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}
	return path
}

func TestReadEnvFile(t *testing.T) {
	body := "\xef\xbb\xbf# comment\n" +
		"\n" +
		"SHIMMER_WORKERS=64\r\n" +
		"  SHIMMER_FORMAT = csv  \n" +
		"export SHIMMER_DB=shimmer.db\n" +
		"SHIMMER_MMDB_CITY=\"My Files/GeoLite2-Country.mmdb\" # quoted\n" +
		"SHIMMER_MMDB_ASN='a#b.mmdb'\n" +
		"SHIMMER_SKIP=socks4 # inline comment\n" +
		"SHIMMER_OUTPUT=out#1.jsonl\n" +
		"SHIMMER_INPUT=\n" +
		"SHIMMER_FETCH=   # nothing but a comment\n" +
		"SHIMMER_CONFIG=#shimmer.json\n" +
		"TZ=Europe/Berlin\n" +
		"SHIMMER_TIMEOUT=5s\n" +
		"SHIMMER_TIMEOUT=7s\n"
	got, err := ReadEnvFile(writeEnv(t, body))
	if err != nil {
		t.Fatalf("ReadEnvFile: %v", err)
	}
	want := map[string]string{
		"SHIMMER_WORKERS":   "64",
		"SHIMMER_FORMAT":    "csv",
		"SHIMMER_DB":        "shimmer.db",
		"SHIMMER_MMDB_CITY": "My Files/GeoLite2-Country.mmdb",
		"SHIMMER_MMDB_ASN":  "a#b.mmdb",
		"SHIMMER_SKIP":      "socks4",
		"SHIMMER_OUTPUT":    "out#1.jsonl",
		"SHIMMER_INPUT":     "",
		"SHIMMER_FETCH":     "",
		"SHIMMER_CONFIG":    "#shimmer.json",
		"TZ":                "Europe/Berlin",
		"SHIMMER_TIMEOUT":   "7s",
	}
	if !maps.Equal(got, want) {
		t.Errorf("ReadEnvFile =\n%v\nwant\n%v", got, want)
	}
}

func TestReadEnvFileRejectsBadLines(t *testing.T) {
	for _, body := range []string{
		"SHIMMER_WORKERS\n",
		"=64\n",
		"1PP=x\n",
		"SHIMMER-WORKERS=64\n",
		"SHIMMER_DB=\"shimmer.db\n",
		"SHIMMER_DB='shimmer.db' extra\n",
	} {
		if _, err := ReadEnvFile(writeEnv(t, body)); err == nil {
			t.Errorf("ReadEnvFile(%q) succeeded, want an error", body)
		}
	}
}

func TestReadEnvFileMissingFails(t *testing.T) {
	_, err := ReadEnvFile(filepath.Join(t.TempDir(), ".env"))
	if !os.IsNotExist(err) {
		t.Errorf("ReadEnvFile of a missing file: %v, want not-exist", err)
	}
}
