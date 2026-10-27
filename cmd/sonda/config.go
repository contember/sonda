package main

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"go.yaml.in/yaml/v3"
	"golang.org/x/term"
)

type fileConfig struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sonda", "config.yaml"), nil
}

// loadConfig reads the config file and warns when its mode exposes the token.
func loadConfig() (fileConfig, error) {
	path, err := configPath()
	if err != nil {
		return fileConfig{}, nil
	}
	if info, err := os.Stat(path); err == nil {
		checkConfigMode(path, info.Mode().Perm(), os.Stdin, os.Stderr, isTerminal(os.Stdin) && isTerminal(os.Stderr))
	}
	return readConfig(path)
}

// readConfig returns the zero config when the file cannot be read.
func readConfig(path string) (fileConfig, error) {
	var file fileConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return file, nil
	}
	if err := yaml.Unmarshal(data, &file); err != nil {
		return file, fmt.Errorf("read sonda config: %w", err)
	}
	return file, nil
}

// saveConfig replaces the file atomically; the new file is created with mode 0600.
func saveConfig(path string, file fileConfig) error {
	data, err := yaml.Marshal(file)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// checkConfigMode warns when other users can access the token, and offers chmod 600 in a terminal.
func checkConfigMode(path string, perm fs.FileMode, in io.Reader, out io.Writer, interactive bool) {
	// Windows has no Unix permission bits; Go reports 0666 for every writable file.
	if runtime.GOOS == "windows" || perm&0o077 == 0 {
		return
	}
	fmt.Fprintf(out, "warning: %s contains your token and is accessible by other users (mode %04o)\n", path, perm)
	if !interactive {
		fmt.Fprintf(out, "fix it with: chmod 600 %s\n", path)
		return
	}
	fmt.Fprint(out, "Restrict it to 0600? [Y/n] ")
	answer, err := bufio.NewReader(in).ReadString('\n')
	if err != nil {
		fmt.Fprintln(out)
		return
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "", "y", "yes":
		if err := os.Chmod(path, 0o600); err != nil {
			fmt.Fprintf(out, "warning: chmod %s: %v\n", path, err)
		}
	}
}

func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
