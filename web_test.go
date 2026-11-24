package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func webEnv(t *testing.T) (*app, *authServer, *admin, *http.ServeMux) {
	a, _ := testApp(t)
	au := newAuthServer(a.db, "https://collab.test")
	ad := newAdmin(a, au)
	mux := http.NewServeMux()
	au.routes(mux)
	ad.routes(mux)
	return a, au, ad, mux
}

func doReq(mux http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func form(method, path string, v url.Values) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestOAuthBindsAgentChosenByHuman(t *testing.T) {
	a, _, _, mux := webEnv(t)
	redirect := "https://chatgpt.com/connector_platform_oauth_redirect"
	rr := doReq(mux, httptest.NewRequest("POST", "/register", strings.NewReader(`{"client_name":"ChatGPT","redirect_uris":["`+redirect+`"]}`)))
	if rr.Code != 201 {
		t.Fatalf("register: %d", rr.Code)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &reg)
	verifier := randToken(40)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	q := url.Values{"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {redirect}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	gr := doReq(mux, httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil))
	if gr.Code != 200 || !strings.Contains(gr.Body.String(), `name="agent"`) || !strings.Contains(gr.Body.String(), `value="chatgpt"`) {
		t.Fatalf("authorise page lacks agent dropdown: %d", gr.Code)
	}
	var csrf string
	for _, c := range gr.Result().Cookies() {
		if c.Name == "csrf" {
			csrf = c.Value
		}
	}
	post := func(agent string) *httptest.ResponseRecorder {
		f := url.Values{"csrf": {csrf}, "client_id": {reg.ClientID}, "redirect_uri": {redirect}, "code_challenge": {challenge},
			"username": {"admin"}, "password": {"correct horse battery"}, "agent": {agent}}
		req := form("POST", "/authorize", f)
		req.AddCookie(&http.Cookie{Name: "csrf", Value: csrf})
		return doReq(mux, req)
	}
	if r := post(""); r.Code != 400 {
		t.Fatalf("missing agent accepted: %d", r.Code)
	}
	if r := post("mallory"); r.Code != 400 {
		t.Fatalf("unknown agent accepted: %d", r.Code)
	}
	r := post("chatgpt")
	if r.Code != 302 {
		t.Fatalf("authorise: %d %s", r.Code, r.Body)
	}
	loc, _ := url.Parse(r.Header().Get("Location"))
	tr := doReq(mux, form("POST", "/token", url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"code_verifier": {verifier}, "client_id": {reg.ClientID}, "redirect_uri": {redirect}}))
	if tr.Code != 200 {
		t.Fatalf("token: %d %s", tr.Code, tr.Body)
	}
	var tok struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	_ = json.Unmarshal(tr.Body.Bytes(), &tok)
	_, agent, ok := lookupToken(a.db, tok.Access)
	if !ok || agent != "chatgpt" {
		t.Fatalf("access token agent=%q ok=%v", agent, ok)
	}
	// refresh keeps the binding
	rr2 := doReq(mux, form("POST", "/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.Refresh}, "client_id": {reg.ClientID}}))
	var tok2 struct {
		Access string `json:"access_token"`
	}
	_ = json.Unmarshal(rr2.Body.Bytes(), &tok2)
	if _, ag, ok := lookupToken(a.db, tok2.Access); !ok || ag != "chatgpt" {
		t.Fatalf("refreshed token agent=%q", ag)
	}
	// A disabled agent cannot be chosen at the authorise step.
	_, _ = a.db.Exec(`UPDATE agents SET enabled=0 WHERE name='claude'`)
	if r := post("claude"); r.Code != 400 {
		t.Fatalf("disabled agent selectable: %d", r.Code)
	}
}

func adminSession(t *testing.T, a *app) (*http.Cookie, string) {
	tok, csrf := randToken(32), randToken(18)
	_, _ = a.db.Exec(`INSERT INTO sessions(hash,csrf,expires) VALUES(?,?,?)`, hashToken(tok), csrf, time.Now().Add(time.Hour).Unix())
	return &http.Cookie{Name: "collabmcp_sess", Value: tok}, csrf
}

func TestDashboardApproveNeedsSessionAndCSRF(t *testing.T) {
	a, _, _, mux := webEnv(t)
	remote := mkRemote(t)
	addProject(t, a, "demo", remote)
	ctx := context.Background()
	_, _ = a.gitBranchStart(ctx, "claude", branchStartIn{"demo", "f"})
	_, _ = a.gitWriteFile(ctx, "claude", writeFileIn{"demo", "f.txt", "x\n"})
	_, _ = a.gitCommit(ctx, "claude", commitIn{"demo", "f"})
	_, _ = a.gitPush(ctx, "claude", projIn{"demo"})
	mr, err := a.mergeRequest(ctx, "claude", mrCreateIn{"demo", "s"})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.reviewPost("chatgpt", reviewIn{mr.ID, "approve", "ok"})
	before := gitRaw(t, remote, "rev-parse", "main")
	id := "1"

	// No session.
	if r := doReq(mux, form("POST", "/admin/mr/approve", url.Values{"id": {id}})); r.Code != 303 {
		t.Fatalf("unauthenticated approve: %d", r.Code)
	}
	// A bearer token for an agent is not a dashboard session.
	req := form("POST", "/admin/mr/approve", url.Values{"id": {id}})
	req.Header.Set("Authorization", "Bearer "+mkToken(t, a, "chatgpt"))
	doReq(mux, req)
	// Session but wrong CSRF.
	ck, csrf := adminSession(t, a)
	req = form("POST", "/admin/mr/approve", url.Values{"id": {id}, "csrf": {"wrong"}})
	req.AddCookie(ck)
	if r := doReq(mux, req); r.Code != 403 {
		t.Fatalf("bad csrf: %d", r.Code)
	}
	if gitRaw(t, remote, "rev-parse", "main") != before {
		t.Fatal("main moved without a valid human action")
	}
	// The detail page renders the diff.
	req = httptest.NewRequest("GET", "/admin/mr?id="+id, nil)
	req.AddCookie(ck)
	pg := doReq(mux, req)
	if pg.Code != 200 || !strings.Contains(pg.Body.String(), "&#43;x") || !strings.Contains(pg.Body.String(), "Approve and merge") {
		t.Fatalf("mr page: %d %s", pg.Code, pg.Body.String())
	}
	// Valid session + CSRF merges.
	req = form("POST", "/admin/mr/approve", url.Values{"id": {id}, "csrf": {csrf}})
	req.AddCookie(ck)
	if r := doReq(mux, req); r.Code != 303 || strings.Contains(r.Header().Get("Location"), "e=") {
		t.Fatalf("approve: %d %s", r.Code, r.Header().Get("Location"))
	}
	if gitRaw(t, remote, "rev-parse", "main") == before {
		t.Fatal("approved request did not merge")
	}
}

func TestDashboardPauseAgentsTokensAndProjects(t *testing.T) {
	a, _, _, mux := webEnv(t)
	ck, csrf := adminSession(t, a)
	do := func(path string, v url.Values) *httptest.ResponseRecorder {
		v.Set("csrf", csrf)
		req := form("POST", path, v)
		req.AddCookie(ck)
		return doReq(mux, req)
	}
	do("/admin/pause", url.Values{"paused": {"1"}})
	if !a.paused() {
		t.Fatal("pause not applied")
	}
	do("/admin/pause", url.Values{"paused": {"0"}})
	do("/admin/agents/toggle", url.Values{"name": {"chatgpt"}, "enabled": {"0"}})
	if a.agentEnabled("chatgpt") {
		t.Fatal("disable not applied")
	}
	do("/admin/agents/toggle", url.Values{"name": {"chatgpt"}, "enabled": {"1"}})

	// token creation binds the chosen agent and is shown once
	r := do("/admin/tokens/new", url.Values{"label": {"gpt main"}, "agent": {"chatgpt"}})
	body := r.Body.String()
	i := strings.Index(body, "collab_")
	if r.Code != 200 || i < 0 {
		t.Fatalf("token page: %d", r.Code)
	}
	tok := body[i : i+7+43]
	if _, ag, ok := lookupToken(a.db, tok); !ok || ag != "chatgpt" {
		t.Fatalf("token agent %q", ag)
	}
	if r := do("/admin/tokens/new", url.Values{"label": {"x"}, "agent": {"nobody"}}); r.Code == 200 {
		t.Fatal("token for unknown agent created")
	}
	// revoke all tokens for the agent
	do("/admin/agents/revoke", url.Values{"name": {"chatgpt"}})
	if _, _, ok := lookupToken(a.db, tok); ok {
		t.Fatal("token survived revoke")
	}
	// project registration validates the remote and encrypts the token
	if r := do("/admin/projects/new", url.Values{"name": {"p1"}, "remote": {"ext::sh -c id"}, "branch": {"main"}}); !strings.Contains(r.Header().Get("Location"), "e=") {
		t.Fatalf("bad remote accepted: %s", r.Header().Get("Location"))
	}
	var n int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM projects`).Scan(&n)
	if n != 0 {
		t.Fatal("project created with bad remote")
	}
	// the dashboard never renders a stored token
	enc, _ := vault.Seal("ghp_DASHBOARDTOKEN0123456789abcdef")
	_, _ = a.db.Exec(`INSERT INTO projects(name,remote,branch,token_enc,created) VALUES('p2','https://example.com/x.git','main',?,1)`, enc)
	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(ck)
	pg := doReq(mux, req)
	if strings.Contains(pg.Body.String(), "DASHBOARDTOKEN") || !strings.Contains(pg.Body.String(), "stored (encrypted)") {
		t.Fatal("dashboard leaks or misreports token")
	}
}

func TestLoginLockoutAndOrigin(t *testing.T) {
	_, _, _, mux := webEnv(t)
	for i := 0; i < 5; i++ {
		r := form("POST", "/admin/login", url.Values{"username": {"admin"}, "password": {"wrong"}})
		r.RemoteAddr = "203.0.113.9:1234"
		if rr := doReq(mux, r); rr.Code != 401 {
			t.Fatalf("attempt %d: %d", i, rr.Code)
		}
	}
	r := form("POST", "/admin/login", url.Values{"username": {"admin"}, "password": {"correct horse battery"}})
	r.RemoteAddr = "203.0.113.9:1234"
	if rr := doReq(mux, r); rr.Code != 429 {
		t.Fatalf("lockout not applied: %d", rr.Code)
	}
	r = form("POST", "/admin/login", url.Values{"username": {"admin"}, "password": {"correct horse battery"}})
	r.Header.Set("Origin", "https://evil.example")
	if rr := doReq(mux, r); rr.Code != 403 {
		t.Fatalf("foreign origin accepted: %d", rr.Code)
	}
}
