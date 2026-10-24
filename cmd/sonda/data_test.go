package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVariablesJSON(t *testing.T) {
	got, err := variablesJSON("", []string{"id=2024", "n:=10", "f:={\"a\":true}", "s=a=b"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"f":{"a":true},"id":"2024","n":10,"s":"a=b"}`; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
	for _, bad := range []string{"novalue", "=x", "n:=nope"} {
		if _, err := variablesJSON("", []string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	file := filepath.Join(t.TempDir(), "vars.json")
	if err := os.WriteFile(file, []byte("null"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := variablesJSON(file, []string{"a=b"}); err != nil || string(got) != `{"a":"b"}` {
		t.Errorf("null vars file: %s, %v", got, err)
	}
	if err := os.WriteFile(file, []byte(`{"a":1} {"b":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := variablesJSON(file, nil); err == nil {
		t.Error("trailing data accepted")
	}
}
