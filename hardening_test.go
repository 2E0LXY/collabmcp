package main

import (
	"context"
	"os"
	"path/filepath"
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

func TestCIPathsBlockedForWrites(t *testing.T) {
	bad := []string{".github/workflows/x.yml", ".GitHub/workflows/x.yml", "a/.github/workflows/x.yml", ".github", "a/.GITHUB",
		".github./x", ".gitlab-ci.yml", "sub/.GitLab-CI.yml", ".circleci/config.yml", "azure-pipelines.yml", "Jenkinsfile", "x/jenkinsfile"}
	for _, p := range bad {
		if err := checkRelPath(p); err == nil {
			t.Errorf("checkRelPath accepted %q", p)
		}
	}
	for _, p := range []string{"docs/github.md", "githubby/x.go", "jenkins.md", "README.md"} {
		if err := checkRelPath(p); err != nil {
			t.Errorf("rejected %q: %v", p, err)
		}
	}
	// .git and .gitmodules stay blocked.
	for _, p := range []string{".git/config", ".gitmodules", "a/.GITMODULES"} {
		if checkRelPath(p) == nil || checkRelPathRead(p) == nil {
			t.Errorf("%q accepted", p)
		}
	}
	// Reads of CI config are allowed.
	if err := checkRelPathRead(".github/workflows/x.yml"); err != nil {
		t.Errorf("read of workflow rejected: %v", err)
	}
}

func TestCIPathsThroughGitTools(t *testing.T) {
	a, remote, p := gitFixture(t)
	_ = remote
	ctx := context.Background()
	if _, err := a.gitBranchStart(ctx, "claude", branchStartIn{p, "ci"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{".github/workflows/x.yml", ".GitHub/workflows/x.yml", "a/.github/workflows/x.yml", "Jenkinsfile"} {
		if _, err := a.gitWriteFile(ctx, "claude", writeFileIn{p, bad, "x"}); err == nil {
			t.Errorf("write accepted %q", bad)
		}
		if _, err := a.gitDeleteFile(ctx, "claude", pathIn{p, bad}); err == nil {
			t.Errorf("delete accepted %q", bad)
		}
	}
	// A file planted by other means is refused at commit time.
	wt := a.git.worktree(p, "claude")
	_ = os.MkdirAll(filepath.Join(wt, ".github", "workflows"), 0o755)
	_ = os.WriteFile(filepath.Join(wt, ".github", "workflows", "x.yml"), []byte("on: push\n"), 0o644)
	if _, err := a.gitCommit(ctx, "claude", commitIn{p, "sneaky"}); err == nil {
		t.Error("commit of .github file accepted")
	}
}
