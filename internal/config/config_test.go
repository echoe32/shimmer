package config

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"shimmer/internal/probe"
)

func writeFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shimmer.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadMergesOverDefaults(t *testing.T) {
	path := writeFile(t, `{"input":"list.txt","db":"shimmer.db","workers":64,"proxy_timeout":"3s","check_exit_ip":true}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Input != "list.txt" || cfg.DB != "shimmer.db" || cfg.Workers != 64 {
		t.Errorf("file values not applied: %+v", cfg)
	}
	if cfg.ProxyTimeout != 3*time.Second {
		t.Errorf("ProxyTimeout = %s, want 3s", cfg.ProxyTimeout)
	}
	if !cfg.CheckExitIP {
		t.Error("CheckExitIP not applied")
	}
	if cfg.Format != Default().Format {
		t.Errorf("Format = %q, want the default %q", cfg.Format, Default().Format)
	}
}

func TestLoadWithoutPathIsDefault(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Errorf("Load(\"\") = %+v, want the defaults", cfg)
	}
}

func TestLoadRejectsUnreadableValues(t *testing.T) {
	for _, body := range []string{
		`{"proxy_timeout":"soon"}`,
		`{"workers":"many"}`,
		`not json`,
		`{"workers":64} {"workers":1}`,
	} {
		if _, err := Load(writeFile(t, body)); err == nil {
			t.Errorf("Load(%s) succeeded, want an error", body)
		}
	}
}

// A misspelt key used to be ignored, and the setting it meant kept its
// default without a word.
func TestLoadRejectsUnknownKeys(t *testing.T) {
	if _, err := Load(writeFile(t, `{"worker":64}`)); err == nil {
		t.Error("Load accepted a misspelt key")
	}
	if _, err := Load(writeFile(t, "{\"workers\":64}\n")); err != nil {
		t.Errorf("Load of a file ending in a newline: %v", err)
	}
}

// Values that parse but are out of range are left to Validate, once the flags
// have had their say. Load used to reject them, and a flag could not correct
// a bad file.
func TestValidateRejectsBadValues(t *testing.T) {
	for _, body := range []string{
		`{"format":"xml"}`,
		`{"workers":0}`,
		`{"proxy_timeout":"-1s"}`,
		`{"db":"-"}`,
		`{"skip_protocols":["socks6"]}`,
		`{"skip_protocols":["unknown"]}`,
		`{"skip_protocols":["socks5","socks4","https","http","vless","vmess","trojan","ss","hysteria2"]}`,
	} {
		cfg, err := Load(writeFile(t, body))
		if err != nil {
			t.Errorf("Load(%s): %v, want the value left for Validate", body, err)
			continue
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate accepted %s", body)
		}
	}
}

func TestLoadMissingFileFails(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("Load of a missing file succeeded")
	}
}

func TestLoadReadsSkippedProtocols(t *testing.T) {
	cfg, err := Load(writeFile(t, `{"skip_protocols":["socks4","http"]}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := []probe.Protocol{probe.SOCKS4, probe.HTTP}; !slices.Equal(cfg.SkipProtocols, want) {
		t.Errorf("SkipProtocols = %v, want %v", cfg.SkipProtocols, want)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}
