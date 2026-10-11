// Package config holds run configuration, assembled from flags and file.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"shimmer/internal/probe"
)

// Config is the whole program's settings.
type Config struct {
	Input        string        // proxy list path, "-" for stdin
	Output       string        // results path
	DB           string        // SQLite database path, empty for none
	Format       string        // jsonl | csv
	Workers      int           // concurrent probes
	ProxyTimeout time.Duration // per-proxy deadline

	MMDBCity string // MaxMind City database path
	MMDBASN  string // MaxMind ASN database path

	CheckExitIP bool // resolve the true exit IP through each proxy

	SkipProtocols []probe.Protocol // protocols whose proxies are left out of the results
}

// Default returns sane starting values.
func Default() Config {
	return Config{
		Format:       "jsonl",
		Workers:      512,
		ProxyTimeout: 10 * time.Second,
	}
}

// fileConfig mirrors Config with pointers, so an absent key leaves the default
// in place instead of zeroing it.
type fileConfig struct {
	Input        *string `json:"input"`
	Output       *string `json:"output"`
	DB           *string `json:"db"`
	Format       *string `json:"format"`
	Workers      *int    `json:"workers"`
	ProxyTimeout *string `json:"proxy_timeout"` // Go duration text, e.g. "10s"

	MMDBCity *string `json:"mmdb_city"`
	MMDBASN  *string `json:"mmdb_asn"`

	CheckExitIP *bool `json:"check_exit_ip"`

	SkipProtocols *[]probe.Protocol `json:"skip_protocols"`
}

// Load merges the file at path (if any) over the defaults. It rejects what
// does not parse, but leaves range checks to Validate: flags still override
// the file, and a flag must be able to correct it.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	var fc fileConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	// A misspelt key used to be ignored without a word, leaving the setting it
	// was meant to change at its default.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fc); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	// Unmarshal refused anything after the object; the decoder stops at it.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return cfg, fmt.Errorf("parse %s: unexpected data after the object", path)
	}

	assign(&cfg.Input, fc.Input)
	assign(&cfg.Output, fc.Output)
	assign(&cfg.DB, fc.DB)
	assign(&cfg.Format, fc.Format)
	assign(&cfg.Workers, fc.Workers)
	assign(&cfg.MMDBCity, fc.MMDBCity)
	assign(&cfg.MMDBASN, fc.MMDBASN)
	assign(&cfg.CheckExitIP, fc.CheckExitIP)
	assign(&cfg.SkipProtocols, fc.SkipProtocols)

	if fc.ProxyTimeout != nil {
		d, err := time.ParseDuration(*fc.ProxyTimeout)
		if err != nil {
			return cfg, fmt.Errorf("parse %s: proxy_timeout: %w", path, err)
		}
		cfg.ProxyTimeout = d
	}
	return cfg, nil
}

func assign[T any](dst *T, src *T) {
	if src != nil {
		*dst = *src
	}
}

// Validate rejects settings that would fail later, in the middle of a run.
func (c Config) Validate() error {
	switch c.Format {
	case "jsonl", "csv":
	default:
		return fmt.Errorf("unknown format %q, want jsonl or csv", c.Format)
	}
	if c.DB == "-" {
		return errors.New("db must name a file, not stdout")
	}
	if c.Workers <= 0 {
		return fmt.Errorf("workers must be positive, got %d", c.Workers)
	}
	if c.ProxyTimeout <= 0 {
		return fmt.Errorf("proxy timeout must be positive, got %s", c.ProxyTimeout)
	}
	return probe.CheckSkip(c.SkipProtocols)
}
