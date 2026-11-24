package main

import (
	"os"
	"strings"
	"testing"
)

func TestWorkflowsPinLatestGoAndVulncheck(t *testing.T) {
	for _, f := range []string{".github/workflows/build.yml", ".github/workflows/release.yml"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, want := range []string{"go-version: '1.26.x'", "check-latest: true", "govulncheck@latest", "govulncheck\" ./..."} {
			if !strings.Contains(s, want) {
				t.Errorf("%s: missing %q", f, want)
			}
		}
		if strings.Contains(s, "go-version-file") {
			t.Errorf("%s: must not use go-version-file", f)
		}
	}
}
