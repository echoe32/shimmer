package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

// ReadEnvFile reads the KEY=VALUE lines of a .env file. It reads the subset
// that Docker Compose also reads, so one file serves both: blank lines and
// lines starting with # are skipped, an "export " prefix is allowed, a value
// may be wrapped in single or double quotes, and an unquoted value ends at a
// # that follows a space. Quoted values are taken as written, with no escape
// sequences. A key given twice keeps its last value.
func ReadEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	vars := make(map[string]string)
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimPrefix(line, "export "), "=")
		key = strings.TrimSpace(key)
		if !ok || !isEnvName(key) {
			return nil, fmt.Errorf("parse %s:%d: want NAME=value", path, i+1)
		}
		value, err := envValue(value)
		if err != nil {
			return nil, fmt.Errorf("parse %s:%d: %s: %w", path, i+1, key, err)
		}
		vars[key] = value
	}
	return vars, nil
}

// envValue unquotes a value and drops a trailing comment. The # of a comment
// must follow a space, which may be the one after the =.
func envValue(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v != "" && (v[0] == '"' || v[0] == '\'') {
		end := strings.IndexByte(v[1:], v[0])
		if end < 0 {
			return "", fmt.Errorf("no closing %c", v[0])
		}
		if rest := strings.TrimSpace(v[end+2:]); rest != "" && !strings.HasPrefix(rest, "#") {
			return "", fmt.Errorf("text after the closing %c", v[0])
		}
		return v[1 : end+1], nil
	}
	for i := 1; i < len(raw); i++ {
		if raw[i] == '#' && (raw[i-1] == ' ' || raw[i-1] == '\t') {
			return strings.TrimSpace(raw[:i]), nil
		}
	}
	return v, nil
}

// isEnvName reports whether s is a shell variable name.
func isEnvName(s string) bool {
	if s == "" || s[0] >= '0' && s[0] <= '9' {
		return false
	}
	for _, c := range []byte(s) {
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
