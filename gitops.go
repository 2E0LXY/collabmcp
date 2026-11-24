package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	gitOutCap       = 1 << 20 // output cap per git invocation
	gitTimeoutLocal = 30 * time.Second
	gitTimeoutNet   = 120 * time.Second
	maxWriteFile    = 256 << 10
)

// ---- path guard ----

var errPath = errors.New("path not permitted")

func pathErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errPath, fmt.Sprintf(format, a...))
}

// secretName reports whether a file's base name looks like it holds secrets.
func secretName(base string) bool {
	b := strings.ToLower(base)
	switch {
	case b == ".env" || strings.HasPrefix(b, ".env."), strings.HasPrefix(b, ".env"):
		return true
	case strings.HasSuffix(b, ".pem"), strings.HasSuffix(b, ".key"):
		return true
	case strings.HasPrefix(b, "id_"):
		return true
	case strings.Contains(b, "credentials"):
		return true
	}
	return false
}

func isDotGit(c string) bool {
	l := strings.ToLower(strings.TrimRight(c, ". "))
	return l == ".git" || l == "git~1" || l == ".gitmodules"
}

// isCIPath reports whether a path component names CI/CD configuration. Agents must not
// write these: a workflow change runs with repository secrets once merged or pushed.
func isCIPath(c string) bool {
	l := strings.ToLower(strings.TrimRight(c, ". "))
	switch l {
	case ".github", ".gitlab-ci.yml", ".circleci", "azure-pipelines.yml", "jenkinsfile":
		return true
	}
	return false
}

// checkRelPath validates a repo-relative path lexically, for writes, deletes and commits
// (CI configuration is off limits).
func checkRelPath(p string) error { return checkPath(p, true) }

// checkRelPathRead is the read-side variant: identical except that CI configuration may be read.
func checkRelPathRead(p string) error { return checkPath(p, false) }

func checkPath(p string, blockCI bool) error {
	switch {
	case p == "":
		return pathErr("empty")
	case len(p) > 400:
		return pathErr("too long")
	case strings.ContainsRune(p, 0):
		return pathErr("NUL byte")
	case strings.Contains(p, `\`):
		return pathErr("backslash")
	case strings.HasPrefix(p, "/") || filepath.IsAbs(p):
		return pathErr("absolute paths are not allowed")
	}
	parts := strings.Split(p, "/")
	for i, c := range parts {
		switch {
		case c == "" || c == ".":
			return pathErr("empty or '.' component")
		case c == "..":
			return pathErr("'..' is not allowed")
		case isDotGit(c):
			return pathErr("anything under .git is off limits")
		case blockCI && isCIPath(c):
			return pathErr("CI/CD configuration (.github, .gitlab-ci.yml, .circleci, azure-pipelines.yml, Jenkinsfile) is off limits")
		case strings.EqualFold(c, ".ssh"):
			return pathErr(".ssh is off limits")
		case i == len(parts)-1 && secretName(c):
			return pathErr("secret-looking file name")
		}
	}
	return nil
}

// safePath returns the absolute path inside root for rel, after lexical checks
// and symlink resolution of every existing ancestor. If forWrite, an existing
// symlink at the final component is refused outright.
func safePath(root, rel string, forWrite bool) (string, error) {
	if err := checkPath(rel, forWrite); err != nil {
		return "", err
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	full := filepath.Join(realRoot, filepath.FromSlash(rel))
	// Resolve the deepest existing ancestor.
	probe := full
	var tail []string
	for {
		if _, err := os.Lstat(probe); err == nil {
			break
		}
		tail = append([]string{filepath.Base(probe)}, tail...)
		next := filepath.Dir(probe)
		if next == probe {
			return "", pathErr("cannot resolve")
		}
		probe = next
	}
	if fi, err := os.Lstat(full); err == nil && fi.Mode()&os.ModeSymlink != 0 && forWrite {
		return "", pathErr("target is a symlink")
	}
	resolved, err := filepath.EvalSymlinks(probe)
	if err != nil {
		return "", pathErr("dangling or looping symlink")
	}
	resolved = filepath.Join(append([]string{resolved}, tail...)...)
	relOut, err := filepath.Rel(realRoot, resolved)
	if err != nil || relOut == ".." || strings.HasPrefix(relOut, ".."+string(filepath.Separator)) {
		return "", pathErr("escapes the worktree")
	}
	for _, c := range strings.Split(filepath.ToSlash(relOut), "/") {
		if isDotGit(c) {
			return "", pathErr("resolves into .git")
		}
		if forWrite && isCIPath(c) {
			return "", pathErr("resolves into CI/CD configuration")
		}
	}
	return resolved, nil
}

// ---- secret scanning of added lines ----

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`),
	regexp.MustCompile(`\bghp_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
}

// scanAdded checks the added lines of a unified diff for secret patterns.
func scanAdded(diff string) error {
	for _, l := range strings.Split(diff, "\n") {
		if !strings.HasPrefix(l, "+") || strings.HasPrefix(l, "+++") {
			continue
		}
		for _, re := range secretPatterns {
			if re.MatchString(l) {
				return errors.New("refused: added lines match a secret pattern (private key, token or AWS key id)")
			}
		}
	}
	return nil
}

// ---- git runner ----

type gitx struct {
	dir string // COLLAB_DIR
}

func (g *gitx) repoDir(project string) string { return filepath.Join(g.dir, "repos", project) }
func (g *gitx) workRoot(project string) string {
	return filepath.Join(g.dir, "work", project)
}
func (g *gitx) worktree(project, agent string) string {
	return filepath.Join(g.workRoot(project), agent)
}

// gitAllowProtocol limits git transports. Production allows https only; tests widen it to local files.
const defaultGitAllowProtocol = "https"

var gitAllowProtocol = defaultGitAllowProtocol

// hardenedArgs are prepended to every git invocation.
var hardenedArgs = []string{
	"-c", "core.hooksPath=/dev/null",
	"-c", "protocol.ext.allow=never",
	"-c", "core.fsmonitor=false",
	"-c", "credential.helper=",
	"-c", "core.askPass=",
	"-c", "diff.external=",
	"-c", "commit.gpgsign=false",
	"-c", "advice.detachedHead=false",
}

type capWriter struct {
	buf bytes.Buffer
	cap int
	hit bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.cap - w.buf.Len(); room > 0 {
		if len(p) > room {
			w.buf.Write(p[:room])
			w.hit = true
		} else {
			w.buf.Write(p)
		}
	} else if len(p) > 0 {
		w.hit = true
	}
	return len(p), nil
}

type gitOpts struct {
	cwd     string
	token   string // injected via a temporary GIT_ASKPASS helper
	timeout time.Duration
	stdin   string
}

// run executes git with exec args only (no shell). Returns capped combined output.
func (g *gitx) run(ctx context.Context, o gitOpts, args ...string) (string, error) {
	if o.timeout == 0 {
		o.timeout = gitTimeoutLocal
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	tmp := filepath.Join(g.dir, "tmp")
	_ = os.MkdirAll(tmp, 0o700)
	home, err := os.MkdirTemp(tmp, "gh-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(home)
	env := []string{
		"PATH=" + env("PATH", "/usr/bin:/bin"),
		"HOME=" + home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL=" + gitAllowProtocol,
		"LC_ALL=C",
	}
	if o.token != "" {
		script := filepath.Join(home, "askpass.sh")
		body := "#!/bin/sh\ncase \"$1\" in\n*sername*) echo x-access-token ;;\n*) printf '%s\\n' \"$COLLAB_GIT_TOKEN\" ;;\nesac\n"
		if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
			return "", err
		}
		env = append(env, "GIT_ASKPASS="+script, "COLLAB_GIT_TOKEN="+o.token)
	}
	full := append(append([]string{}, hardenedArgs...), args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = o.cwd
	cmd.Env = env
	if o.stdin != "" {
		cmd.Stdin = strings.NewReader(o.stdin)
	}
	out := &capWriter{cap: gitOutCap}
	cmd.Stdout, cmd.Stderr = out, out
	err = cmd.Run()
	s := out.buf.String()
	if o.token != "" {
		s = strings.ReplaceAll(s, o.token, "***")
	}
	if out.hit {
		s += "\n[output truncated]"
	}
	if ctx.Err() == context.DeadlineExceeded {
		return s, errors.New("git timed out")
	}
	if err != nil {
		return s, fmt.Errorf("git %s failed: %s", firstArg(args), strings.TrimSpace(lastLines(s, 5)))
	}
	return s, nil
}

func firstArg(a []string) string {
	if len(a) > 0 {
		return a[0]
	}
	return ""
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

// ---- validators ----

var (
	reProject = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,39}$`)
	reTopic   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,59}$`)
	reRev     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/@^~{}-]{0,199}$`)
	reBranch  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/-]{0,99}$`)
)

func validRev(r string) error {
	if !reRev.MatchString(r) || strings.Contains(r, "..") || strings.Contains(r, "@{") {
		return fmt.Errorf("invalid revision %q", r)
	}
	return nil
}

func validBranchName(b string) bool {
	return reBranch.MatchString(b) && !strings.Contains(b, "..") && !strings.HasSuffix(b, "/") &&
		!strings.HasSuffix(b, ".lock") && !strings.Contains(b, "//")
}

// validRemote accepts https URLs only (local paths only when allowLocal, for tests).
func validRemote(u string, allowLocal bool) bool {
	if strings.HasPrefix(u, "https://") && !strings.ContainsAny(u, " \t\r\n\x00") && !strings.Contains(u, "@") {
		return len(u) < 300
	}
	return allowLocal && strings.HasPrefix(u, "/")
}

// ---- project git operations ----

func (g *gitx) ensureRepo(ctx context.Context, p *project) error {
	rd := g.repoDir(p.Name)
	if _, err := os.Stat(filepath.Join(rd, "HEAD")); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(rd), 0o700); err != nil {
		return err
	}
	if _, err := g.run(ctx, gitOpts{cwd: filepath.Dir(rd), token: p.Token, timeout: gitTimeoutNet},
		"clone", "--bare", "--", p.Remote, rd); err != nil {
		_ = os.RemoveAll(rd)
		return err
	}
	if _, err := g.run(ctx, gitOpts{cwd: rd}, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"); err != nil {
		return err
	}
	return g.fetch(ctx, p)
}

func (g *gitx) fetch(ctx context.Context, p *project) error {
	_, err := g.run(ctx, gitOpts{cwd: g.repoDir(p.Name), token: p.Token, timeout: gitTimeoutNet},
		"fetch", "--prune", "origin")
	return err
}

func (g *gitx) ensureWorktree(ctx context.Context, p *project, agent string) (string, error) {
	wt := g.worktree(p.Name, agent)
	if _, err := os.Stat(filepath.Join(wt, ".git")); err == nil {
		return wt, nil
	}
	if err := os.MkdirAll(filepath.Dir(wt), 0o700); err != nil {
		return "", err
	}
	if _, err := g.run(ctx, gitOpts{cwd: g.repoDir(p.Name)}, "worktree", "prune"); err != nil {
		return "", err
	}
	if _, err := g.run(ctx, gitOpts{cwd: g.repoDir(p.Name)}, "worktree", "add", "--detach", wt, "refs/remotes/origin/"+p.Branch); err != nil {
		return "", err
	}
	return wt, nil
}

func (g *gitx) currentBranch(ctx context.Context, wt string) (string, error) {
	out, err := g.run(ctx, gitOpts{cwd: wt}, "symbolic-ref", "--short", "-q", "HEAD")
	return strings.TrimSpace(out), err
}

// pushAllowed enforces the push rules: own prefix only, never the default branch.
func pushAllowed(agent, branch, defaultBranch string) error {
	switch {
	case branch == "":
		return errors.New("worktree is not on a branch; call git_branch_start first")
	case branch == defaultBranch:
		return errors.New("pushing the default branch is not permitted")
	case !strings.HasPrefix(branch, agent+"/"):
		return fmt.Errorf("only branches under %s/ may be pushed", agent)
	case strings.ContainsAny(branch, "+: \t\n"):
		return errors.New("invalid branch name")
	}
	return nil
}
