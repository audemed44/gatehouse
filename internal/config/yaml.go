package config

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// ExportYAML renders the config for keeping in a git repo. Basic-auth
// users keep their bcrypt hashes; there are no other secrets in it.
func ExportYAML(c Config) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("# Gatehouse configuration. Import it in Settings, or put it at\n# /data/gatehouse.yaml before the first start.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ParseYAML reads an exported config and validates it.
func ParseYAML(raw []byte) (Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("YAML: %w", err)
	}
	c.Normalize()
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}
