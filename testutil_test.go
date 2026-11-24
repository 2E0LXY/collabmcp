package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func testApp(t *testing.T) (*app, *clock) {
	t.Helper()
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	vault, err = loadVault(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	h, _ := bcrypt.GenerateFromPassword([]byte("correct horse battery"), bcrypt.MinCost)
	_ = setSetting(db, "pw_hash", string(h))
	_ = setSetting(db, "admin_user", "admin")
	a := newApp(db, filepath.Join(dir, "data"))
	c := &clock{t: time.Now()}
	a.now = c.now
	return a, c
}

func gitRaw(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-c", "user.name=seed", "-c", "user.email=seed@example.invalid", "-c", "init.defaultBranch=main"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// mkRemote builds a bare "remote" with one commit on main.
func mkRemote(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	seed := filepath.Join(d, "seed")
	_ = os.MkdirAll(seed, 0o755)
	gitRaw(t, seed, "init", "-q", "-b", "main")
	_ = os.WriteFile(filepath.Join(seed, "README.md"), []byte("hello\n"), 0o644)
	gitRaw(t, seed, "add", "-A")
	gitRaw(t, seed, "commit", "-q", "-m", "init")
	remote := filepath.Join(d, "remote.git")
	gitRaw(t, d, "clone", "-q", "--bare", seed, remote)
	return remote
}

func init() { gitAllowProtocol = "https:file" }

func addProject(t *testing.T, a *app, name, remote string) {
	t.Helper()
	if _, err := a.db.Exec(`INSERT OR REPLACE INTO projects(name,remote,branch,created) VALUES(?,?,?,?)`, name, remote, "main", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
}

func mkToken(t *testing.T, a *app, agent string) string {
	t.Helper()
	tok := "collab_" + randToken(24)
	_, err := a.db.Exec(`INSERT INTO oauth_tokens(hash,kind,client_id,agent,expires) VALUES(?,?,?,?,?)`, hashToken(tok), "access", "c-"+agent, agent, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func ctxAs(agent string) context.Context { return withAgent(context.Background(), agent) }

// rpc posts a JSON-RPC request to the real HTTP stack (bearer + MCP handler).
func rpc(t *testing.T, h http.Handler, tok, method string, params any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(string(body)))
	r.Host = "collab.test"
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != 200 {
		t.Fatalf("rpc %s: %d %s", method, rr.Code, rr.Body)
	}
	raw := rr.Body.String()
	for _, l := range strings.Split(raw, "\n") {
		if strings.HasPrefix(l, "data:") {
			raw = strings.TrimSpace(strings.TrimPrefix(l, "data:"))
			break
		}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("bad rpc body %q: %v", raw, err)
	}
	return out
}

func mcpStack(a *app) http.Handler {
	return bearer(a.db, "https://collab.test", newMCPHandler(a, "collab.test"))
}

func toolList(t *testing.T, a *app) []map[string]any {
	t.Helper()
	tok := mkToken(t, a, "claude")
	res := rpc(t, mcpStack(a), tok, "tools/list", map[string]any{})
	var out []map[string]any
	for _, x := range res["result"].(map[string]any)["tools"].([]any) {
		out = append(out, x.(map[string]any))
	}
	return out
}

// testAppWithProjects is testApp plus dummy registered projects "p" and "proj" for task and lock tests.
func testAppWithProjects(t *testing.T) (*app, *clock) {
	t.Helper()
	a, c := testApp(t)
	for _, n := range []string{"p", "proj"} {
		_, _ = a.db.Exec(`INSERT OR IGNORE INTO projects(name,remote,branch,created) VALUES(?,?,?,?)`, n, "https://example.invalid/"+n, "main", 1)
	}
	return a, c
}
