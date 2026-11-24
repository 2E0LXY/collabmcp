package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckRelPath(t *testing.T) {
	bad := []string{"", "/etc/passwd", "../x", "a/../../x", "a/..", ".git/config", "sub/.git/hooks/pre-commit", ".GIT/config", ".git", ".gitmodules",
		"a//b", "./a", "a\\b", ".env", ".env.local", "config/.env.production", "server.pem", "a/b/key.KEY", "id_rsa", "dir/id_ed25519",
		"aws-credentials.json", "credentials", ".ssh/authorized_keys", "x\x00y", ".git /config", ".git./config"}
	for _, p := range bad {
		if err := checkRelPath(p); err == nil {
			t.Errorf("accepted %q", p)
		}
	}
	for _, p := range []string{"README.md", "src/main.go", "docs/environment.md", "a/b/c.txt", "identity.go", "my.keyboard.md"} {
		if err := checkRelPath(p); err != nil {
			t.Errorf("rejected %q: %v", p, err)
		}
	}
}

func TestSafePathSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, ".git"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "real"), 0o755)
	_ = os.WriteFile(filepath.Join(outside, "f"), []byte("x"), 0o644)
	_ = os.Symlink(outside, filepath.Join(root, "esc"))                          // directory symlink out
	_ = os.Symlink(filepath.Join(outside, "f"), filepath.Join(root, "esc-file")) // file symlink out
	_ = os.Symlink(".git", filepath.Join(root, "dotgit"))                        // inside, but into .git
	_ = os.Symlink("real", filepath.Join(root, "ok-dir"))                        // harmless in-tree link
	_ = os.Symlink("real/x", filepath.Join(root, "ok-file"))
	for _, p := range []string{"esc/new.txt", "esc/f", "esc-file", "dotgit/config", "dotgit/hooks/x"} {
		if _, err := safePath(root, p, true); err == nil {
			t.Errorf("write accepted %q", p)
		}
	}
	if _, err := safePath(root, "esc-file", false); err == nil {
		t.Error("read through escaping file symlink accepted")
	}
	if _, err := safePath(root, "ok-file", true); err == nil {
		t.Error("write to symlink accepted")
	}
	if p, err := safePath(root, "ok-dir/new.txt", true); err != nil || !strings.HasSuffix(p, "real/new.txt") {
		t.Errorf("in-tree dir symlink: %q %v", p, err)
	}
	if _, err := safePath(root, "newdir/deeper/file.txt", true); err != nil {
		t.Errorf("new nested path rejected: %v", err)
	}
}

func TestSecretScan(t *testing.T) {
	bad := []string{
		"+-----BEGIN RSA PRIVATE KEY-----", "+-----BEGIN OPENSSH PRIVATE KEY-----", "+-----BEGIN PRIVATE KEY-----",
		"+token = ghp_abcdefghijklmnopqrstuvwxyz0123456789", "+x github_pat_11ABCDEFG0abcdefghijklmnop_qrstuvwxyz",
		"+aws AKIAIOSFODNN7EXAMPLE", "+aws ASIAIOSFODNN7EXAMPLE",
	}
	for _, l := range bad {
		if err := scanAdded("diff --git a/x b/x\n+++ b/x\n@@ -0,0 +1 @@\n" + l + "\n"); err == nil {
			t.Errorf("missed %q", l)
		}
	}
	ok := "+++ b/x\n+just text\n-ghp_abcdefghijklmnopqrstuvwxyz0123456789 (removed line)\n context AKIAIOSFODNN7EXAMPLE\n"
	if err := scanAdded(ok); err != nil {
		t.Errorf("false positive: %v", err)
	}
}

func TestPushAllowed(t *testing.T) {
	cases := []struct {
		agent, branch string
		ok            bool
	}{
		{"claude", "claude/topic", true}, {"claude", "main", false}, {"claude", "chatgpt/topic", false},
		{"claude", "", false}, {"claude", "claude", false}, {"claude", "claude/a:b", false}, {"claude", "+claude/x", false},
		{"claude", "claudex/y", false},
	}
	for _, c := range cases {
		if err := pushAllowed(c.agent, c.branch, "main"); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c, err)
		}
	}
	if err := pushAllowed("claude", "claude/main", "claude/main"); err == nil {
		t.Error("default branch under own prefix accepted")
	}
}

func TestValidRemoteAndRev(t *testing.T) {
	for _, u := range []string{"ext::sh -c evil", "file:///etc", "ssh://x/y", "git@github.com:a/b", "https://user:pw@github.com/a/b", "http://x/y", "--upload-pack=x", "/local/path"} {
		if validRemote(u, false) {
			t.Errorf("remote accepted %q", u)
		}
	}
	if !validRemote("https://github.com/2E0LXY/x.git", false) {
		t.Error("good remote rejected")
	}
	for _, r := range []string{"-x", "--output=/tmp/x", "a..b", "a b", "main@{1}", "", "$(id)", "a;b"} {
		if validRev(r) == nil {
			t.Errorf("rev accepted %q", r)
		}
	}
	for _, r := range []string{"main", "origin/main", "claude/topic", "HEAD~2", "abc1234", "v1.0"} {
		if err := validRev(r); err != nil {
			t.Errorf("rev rejected %q", r)
		}
	}
}

func TestGitRunnerHardening(t *testing.T) {
	a, _ := testApp(t)
	joined := strings.Join(hardenedArgs, " ")
	for _, want := range []string{"core.hooksPath=/dev/null", "protocol.ext.allow=never"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s", want)
		}
	}
	ctx := context.Background()
	wd := t.TempDir()
	out, err := a.git.run(ctx, gitOpts{cwd: wd}, "config", "--get", "core.hooksPath")
	if err != nil || strings.TrimSpace(out) != "/dev/null" {
		t.Fatalf("hooksPath: %q %v", out, err)
	}
	// Token reaches git only through the environment and is redacted from output.
	out, err = a.git.run(ctx, gitOpts{cwd: wd, token: "tok-SECRET-123"}, "-c", "alias.leak=!echo $COLLAB_GIT_TOKEN; echo $GIT_CONFIG_NOSYSTEM; echo $GIT_ASKPASS", "leak")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "tok-SECRET-123") || !strings.Contains(out, "***") {
		t.Fatalf("token not redacted: %q", out)
	}
	if !strings.Contains(out, "\n1\n") {
		t.Fatalf("GIT_CONFIG_NOSYSTEM not set: %q", out)
	}
	if !strings.Contains(out, "askpass.sh") {
		t.Fatalf("askpass helper not used: %q", out)
	}
	// Helper is removed afterwards.
	left, _ := filepath.Glob(filepath.Join(a.dir, "tmp", "gh-*"))
	if len(left) != 0 {
		t.Fatalf("temp helper left behind: %v", left)
	}
	// ext:: transport is refused.
	if _, err := a.git.run(ctx, gitOpts{cwd: wd}, "ls-remote", "ext::sh -c 'touch "+filepath.Join(wd, "pwned")+"'"); err == nil {
		t.Fatal("ext transport ran")
	}
	if pathExists(filepath.Join(wd, "pwned")) {
		t.Fatal("ext transport executed a command")
	}
	// Output cap.
	out, _ = a.git.run(ctx, gitOpts{cwd: wd}, "-c", "alias.big=!head -c 3000000 /dev/zero | tr '\\0' a", "big")
	if len(out) > gitOutCap+64 || !strings.Contains(out, "truncated") {
		t.Fatalf("output not capped: %d", len(out))
	}
}

// fixture: remote + registered project + claude branch started.
func gitFixture(t *testing.T) (*app, string, string) {
	t.Helper()
	a, _ := testApp(t)
	remote := mkRemote(t)
	addProject(t, a, "demo", remote)
	return a, remote, "demo"
}

func TestGitFlowAndGuardrails(t *testing.T) {
	a, remote, p := gitFixture(t)
	ctx := context.Background()

	if _, err := a.gitStatus(ctx, "claude", projIn{p}); err == nil {
		t.Fatal("status before worktree should fail")
	}
	if _, err := a.gitWriteFile(ctx, "claude", writeFileIn{p, "a.txt", "x"}); err == nil {
		t.Fatal("write before branch start should fail")
	}
	if _, err := a.gitBranchStart(ctx, "claude", branchStartIn{p, "Bad Topic"}); err == nil {
		t.Fatal("bad topic accepted")
	}
	br, err := a.gitBranchStart(ctx, "claude", branchStartIn{p, "feature"})
	if err != nil || br.Branch != "claude/feature" {
		t.Fatalf("branch start: %+v %v", br, err)
	}
	if _, err := a.gitBranchStart(ctx, "claude", branchStartIn{p, "feature"}); err == nil {
		t.Fatal("duplicate branch accepted")
	}

	// write guardrails through the tool layer
	for _, bad := range []string{"../escape.txt", "/tmp/abs.txt", ".git/config", "x/.git/hooks/pre-commit", ".env", "deploy/server.pem", "id_rsa", "my-credentials.json"} {
		if _, err := a.gitWriteFile(ctx, "claude", writeFileIn{p, bad, "x"}); err == nil {
			t.Errorf("write accepted %q", bad)
		}
		if _, err := a.gitDeleteFile(ctx, "claude", pathIn{p, bad}); err == nil {
			t.Errorf("delete accepted %q", bad)
		}
		if _, err := a.gitReadFile(ctx, "claude", pathIn{p, bad}); err == nil {
			t.Errorf("read accepted %q", bad)
		}
	}
	if _, err := a.gitWriteFile(ctx, "claude", writeFileIn{p, "big.txt", strings.Repeat("a", maxWriteFile+1)}); err == nil {
		t.Fatal("oversize content accepted")
	}
	// symlink escape inside the worktree
	wt := a.git.worktree(p, "claude")
	_ = os.Symlink(t.TempDir(), filepath.Join(wt, "link"))
	if _, err := a.gitWriteFile(ctx, "claude", writeFileIn{p, "link/x.txt", "x"}); err == nil {
		t.Fatal("write through escaping symlink accepted")
	}
	_ = os.Remove(filepath.Join(wt, "link"))

	// secret content is refused at commit and the index is left clean
	_, _ = a.gitWriteFile(ctx, "claude", writeFileIn{p, "notes.txt", "key: ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"})
	if _, err := a.gitCommit(ctx, "claude", commitIn{p, "add notes"}); err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatalf("secret commit not refused: %v", err)
	}
	if st, _ := a.git.run(ctx, gitOpts{cwd: wt}, "diff", "--cached", "--name-only"); strings.TrimSpace(st) != "" {
		t.Fatalf("index not cleaned: %q", st)
	}
	if _, err := a.gitDiscard(ctx, "claude", projIn{p}); err != nil {
		t.Fatal(err)
	}
	if pathExists(filepath.Join(wt, "notes.txt")) {
		t.Fatal("discard left file")
	}
	// private key block and AWS id
	_, _ = a.gitWriteFile(ctx, "claude", writeFileIn{p, "k.txt", "-----BEGIN OPENSSH PRIVATE KEY-----\n"})
	if _, err := a.gitCommit(ctx, "claude", commitIn{p, "k"}); err == nil {
		t.Fatal("private key commit accepted")
	}
	_, _ = a.gitDiscard(ctx, "claude", projIn{p})

	// hooks must not run (a pre-commit hook in the repo would write a marker)
	marker := filepath.Join(t.TempDir(), "hook-ran")
	hook := filepath.Join(a.git.repoDir(p), "hooks", "pre-commit")
	_ = os.MkdirAll(filepath.Dir(hook), 0o755)
	_ = os.WriteFile(hook, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755)

	if _, err := a.gitWriteFile(ctx, "claude", writeFileIn{p, "docs/new.md", "# new\n"}); err != nil {
		t.Fatal(err)
	}
	if got, err := a.gitReadFile(ctx, "claude", pathIn{p, "docs/new.md"}); err != nil || got.Content != "# new\n" {
		t.Fatalf("read back: %+v %v", got, err)
	}
	cm, err := a.gitCommit(ctx, "claude", commitIn{p, "add docs"})
	if err != nil || len(cm.Commit) != 40 {
		t.Fatalf("commit: %+v %v", cm, err)
	}
	if pathExists(marker) {
		t.Fatal("repository hook executed")
	}
	if _, err := a.gitCommit(ctx, "claude", commitIn{p, "again"}); err == nil {
		t.Fatal("empty commit accepted")
	}
	lg, _ := a.gitLog(ctx, "claude", gitLogIn{Project: p, Ref: "claude/feature", N: 5})
	if !strings.Contains(lg.Output, "claude") || !strings.Contains(lg.Output, "add docs") || lg.Notice == "" {
		t.Fatalf("log: %+v", lg)
	}
	if _, err := a.gitLog(ctx, "claude", gitLogIn{Project: p, Ref: "--output=/tmp/x"}); err == nil {
		t.Fatal("option-like ref accepted")
	}
	if sh, err := a.gitShow(ctx, "claude", gitShowIn{p, "claude/feature", "docs/new.md"}); err != nil || sh.Output != "# new\n" {
		t.Fatalf("show: %+v %v", sh, err)
	}
	if _, err := a.gitShow(ctx, "claude", gitShowIn{Project: p, Rev: "claude/feature", Path: ".env"}); err == nil {
		t.Fatal("show of secret path accepted")
	}
	df, err := a.gitDiff(ctx, "claude", gitDiffIn{p, "origin/main", "claude/feature"})
	if err != nil || !strings.Contains(df.Output, "+# new") {
		t.Fatalf("diff: %+v %v", df, err)
	}
	if bs, _ := a.gitBranches(ctx, "claude", projIn{p}); !strings.Contains(bs.Output, "claude/feature") {
		t.Fatalf("branches: %q", bs.Output)
	}

	// Push: own branch only; never default; other agent cannot push claude's branch
	if _, err := a.gitBranchStart(ctx, "chatgpt", branchStartIn{p, "other"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.gitPush(ctx, "claude", projIn{p}); err != nil {
		t.Fatalf("own push: %v", err)
	}
	if got := gitRaw(t, remote, "rev-parse", "refs/heads/claude/feature"); got != cm.Commit {
		t.Fatalf("remote head %s != %s", got, cm.Commit)
	}
	// Move the claude worktree onto main (detached) and prove a push is refused
	_, _ = a.git.run(ctx, gitOpts{cwd: wt}, "checkout", "-q", "-B", "main")
	if _, err := a.gitPush(ctx, "claude", projIn{p}); err == nil {
		t.Fatal("push of default branch accepted")
	}
	_, _ = a.git.run(ctx, gitOpts{cwd: wt}, "checkout", "-q", "-B", "chatgpt/other")
	if _, err := a.gitPush(ctx, "claude", projIn{p}); err == nil {
		t.Fatal("push of other agent's prefix accepted")
	}
	if _, err := a.gitWriteFile(ctx, "claude", writeFileIn{p, "x.txt", "x"}); err == nil {
		t.Fatal("write on another agent's branch accepted")
	}
	// Non-fast-forward is not forced.
	_, _ = a.git.run(ctx, gitOpts{cwd: wt}, "checkout", "-q", "claude/feature")
	_, _ = a.git.run(ctx, gitOpts{cwd: wt}, "-c", "user.name=x", "-c", "user.email=x@x", "commit", "--amend", "-q", "--allow-empty", "-m", "rewritten")
	if _, err := a.gitPush(ctx, "claude", projIn{p}); err == nil {
		t.Fatal("non-fast-forward push accepted (force?)")
	}
	if got := gitRaw(t, remote, "rev-parse", "refs/heads/claude/feature"); got != cm.Commit {
		t.Fatal("remote branch was rewritten")
	}
	// default branch on the remote is untouched
	if gitRaw(t, remote, "log", "--oneline", "main"); gitRaw(t, remote, "rev-list", "--count", "main") != "1" {
		t.Fatal("main changed")
	}
}

func TestMergeOnlyViaHumanApproval(t *testing.T) {
	a, remote, p := gitFixture(t)
	ctx := context.Background()
	mainBefore := gitRaw(t, remote, "rev-parse", "main")

	_, _ = a.gitBranchStart(ctx, "claude", branchStartIn{p, "feat"})
	_, _ = a.gitWriteFile(ctx, "claude", writeFileIn{p, "f.txt", "feature\n"})
	if _, err := a.gitCommit(ctx, "claude", commitIn{p, "feature"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.mergeRequest(ctx, "claude", mrCreateIn{p, "adds f.txt"}); err == nil {
		t.Fatal("merge request for an unpushed branch accepted")
	}
	if _, err := a.gitPush(ctx, "claude", projIn{p}); err != nil {
		t.Fatal(err)
	}
	mr, err := a.mergeRequest(ctx, "claude", mrCreateIn{p, "adds f.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.mergeRequest(ctx, "claude", mrCreateIn{p, "again"}); err == nil {
		t.Fatal("duplicate open request accepted")
	}
	// the author cannot review; the peer can
	if _, err := a.reviewPost("claude", reviewIn{mr.ID, "approve", "lgtm"}); err == nil {
		t.Fatal("author reviewed own request")
	}
	if _, err := a.reviewPost("chatgpt", reviewIn{mr.ID, "maybe", "x"}); err == nil {
		t.Fatal("bad verdict accepted")
	}
	// Even a forged author row cannot count: insert it directly and check the tally.
	_, _ = a.db.Exec(`INSERT INTO reviews(mr_id,reviewer,verdict,body,ts) VALUES(?,?,?,?,?)`, mr.ID, "claude", "approve", "self", 1)
	if ap, _ := a.peerApproval(mr.ID, "claude"); ap != 0 {
		t.Fatal("author's own approval counted")
	}
	if err := a.approveMR(ctx, mr.ID, false); err == nil {
		t.Fatal("merged without a peer approval")
	}
	if _, err := a.reviewPost("chatgpt", reviewIn{mr.ID, "approve", "lgtm"}); err != nil {
		t.Fatal(err)
	}
	// A peer approving through the tool must not merge anything.
	if got := gitRaw(t, remote, "rev-parse", "main"); got != mainBefore {
		t.Fatal("default branch moved before human approval")
	}
	var status string
	_ = a.db.QueryRow(`SELECT status FROM merge_requests WHERE id=?`, mr.ID).Scan(&status)
	if status != "open" {
		t.Fatalf("status %s after peer approval", status)
	}
	// No MCP tool can reach approval: the registered tool set has no approve/merge entry point.
	for _, tl := range toolList(t, a) {
		n := tl["name"].(string)
		if (strings.Contains(n, "merge") || strings.Contains(n, "approve")) && n != "merge_request" && n != "merge_request_list" {
			t.Errorf("unexpected merge-capable tool %s", n)
		}
	}
	// Human approval (the dashboard handler's only action) merges with --no-ff and pushes.
	if err := a.approveMR(ctx, mr.ID, false); err != nil {
		t.Fatalf("approve: %v", err)
	}
	after := gitRaw(t, remote, "rev-parse", "main")
	if after == mainBefore {
		t.Fatal("main did not move")
	}
	if parents := strings.Fields(gitRaw(t, remote, "log", "-1", "--format=%P", "main")); len(parents) != 2 {
		t.Fatalf("not a --no-ff merge commit: %v", parents)
	}
	if gitRaw(t, remote, "show", "main:f.txt") != "feature" {
		t.Fatal("merged content missing")
	}
	if err := a.approveMR(ctx, mr.ID, true); err == nil {
		t.Fatal("already merged request approved again")
	}
}

func TestApproveRefusesMovedBranchAndChangeRequests(t *testing.T) {
	a, remote, p := gitFixture(t)
	ctx := context.Background()
	_, _ = a.gitBranchStart(ctx, "chatgpt", branchStartIn{p, "x"})
	_, _ = a.gitWriteFile(ctx, "chatgpt", writeFileIn{p, "g.txt", "1\n"})
	_, _ = a.gitCommit(ctx, "chatgpt", commitIn{p, "g"})
	_, _ = a.gitPush(ctx, "chatgpt", projIn{p})
	mr, err := a.mergeRequest(ctx, "chatgpt", mrCreateIn{p, "g"})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.reviewPost("claude", reviewIn{mr.ID, "approve", "ok"})
	_, _ = a.reviewPost("claude", reviewIn{mr.ID, "changes", "actually no"})
	if err := a.approveMR(ctx, mr.ID, false); err == nil {
		t.Fatal("merged despite outstanding change request")
	}
	// the author pushes another commit after review: approval must refuse the stale request
	_, _ = a.gitWriteFile(ctx, "chatgpt", writeFileIn{p, "h.txt", "2\n"})
	_, _ = a.gitCommit(ctx, "chatgpt", commitIn{p, "h"})
	_, _ = a.gitPush(ctx, "chatgpt", projIn{p})
	if err := a.approveMR(ctx, mr.ID, true); err == nil || !strings.Contains(err.Error(), "moved") {
		t.Fatalf("stale head accepted: %v", err)
	}
	if gitRaw(t, remote, "rev-list", "--count", "main") != "1" {
		t.Fatal("main moved")
	}
	// reject path
	mr2, _ := a.mergeRequest(ctx, "chatgpt", mrCreateIn{p, "again"})
	if err := a.rejectMR(mr2.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.approveMR(ctx, mr2.ID, true); err == nil {
		t.Fatal("rejected request approved")
	}
}

func TestProjectListHidesToken(t *testing.T) {
	a, _ := testApp(t)
	enc, _ := vault.Seal("ghp_SUPERSECRETTOKENVALUE0123456789")
	_, _ = a.db.Exec(`INSERT INTO projects(name,remote,branch,token_enc,created) VALUES('p','https://example.com/a.git','main',?,1)`, enc)
	out, _ := a.projectList("claude")
	b := summarise(out)
	if strings.Contains(b, "SUPERSECRET") || strings.Contains(b, enc) {
		t.Fatalf("token leaked: %s", b)
	}
	p, err := a.loadProject("p")
	if err != nil || p.Token != "ghp_SUPERSECRETTOKENVALUE0123456789" {
		t.Fatalf("token not recoverable by the server: %v", err)
	}
	var stored string
	_ = a.db.QueryRow(`SELECT token_enc FROM projects`).Scan(&stored)
	if strings.Contains(stored, "SUPERSECRET") {
		t.Fatal("token stored in clear")
	}
}

func TestDefaultBranchCorrectedOnFetch(t *testing.T) {
	a, _ := testApp(t)
	remote := mkRemote(t)
	// Rename the remote's default branch so the registered "main" no longer exists there.
	gitRaw(t, remote, "branch", "-m", "main", "trunk")
	gitRaw(t, remote, "symbolic-ref", "HEAD", "refs/heads/trunk")
	addProject(t, a, "p", remote) // registered with branch "main"
	if _, err := a.gitFetch(ctxAs("claude"), "claude", projIn{Project: "p"}); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	p, err := a.loadProject("p")
	if err != nil || p.Branch != "trunk" {
		t.Fatalf("default branch not corrected: %v %v", p, err)
	}
	if _, err := a.gitBranchStart(ctxAs("claude"), "claude", branchStartIn{Project: "p", Topic: "x"}); err != nil {
		t.Fatalf("branch start after correction: %v", err)
	}
}

func TestDefaultBranchCorrectedAfterRemoteRenameFollowingFirstFetch(t *testing.T) {
	a, _ := testApp(t)
	remote := mkRemote(t)
	addProject(t, a, "p", remote) // branch "main", exists
	if _, err := a.gitFetch(ctxAs("claude"), "claude", projIn{Project: "p"}); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	// Remote renames its default AFTER the initial clone; the local bare HEAD is now stale.
	gitRaw(t, remote, "branch", "-m", "main", "trunk")
	gitRaw(t, remote, "symbolic-ref", "HEAD", "refs/heads/trunk")
	if _, err := a.gitFetch(ctxAs("claude"), "claude", projIn{Project: "p"}); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	p, err := a.loadProject("p")
	if err != nil || p.Branch != "trunk" {
		t.Fatalf("stale HEAD not handled: %v %v", p, err)
	}
}
