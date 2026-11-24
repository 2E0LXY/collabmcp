package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const sessionTTL = 12 * time.Hour

var reLabel = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,40}$`)

type admin struct {
	app  *app
	db   *sql.DB
	auth *authServer
	mu   sync.Mutex
}

func newAdmin(a *app, au *authServer) *admin {
	return &admin{app: a, db: a.db, auth: au}
}

// ---- sessions ----

func (ad *admin) newSession(w http.ResponseWriter) {
	tok, csrf := randToken(32), randToken(18)
	_, _ = ad.db.Exec(`INSERT INTO sessions(hash,csrf,expires) VALUES(?,?,?)`, hashToken(tok), csrf, time.Now().Add(sessionTTL).Unix())
	http.SetCookie(w, &http.Cookie{Name: "collabmcp_sess", Value: tok, Path: "/admin", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
}

func (ad *admin) session(r *http.Request) (csrf, key string, ok bool) {
	c, err := r.Cookie("collabmcp_sess")
	if err != nil {
		return "", "", false
	}
	var exp int64
	h := hashToken(c.Value)
	if err := ad.db.QueryRow(`SELECT csrf,expires FROM sessions WHERE hash=?`, h).Scan(&csrf, &exp); err != nil || time.Now().Unix() > exp {
		return "", "", false
	}
	return csrf, h, true
}

// guard wraps POST handlers: valid session + CSRF token.
func (ad *admin) guard(fn func(w http.ResponseWriter, r *http.Request, sess string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secHeaders(w)
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		csrf, sess, ok := ad.session(r)
		if !ok {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		if err := r.ParseForm(); err != nil || subtle.ConstantTimeCompare([]byte(csrf), []byte(r.PostForm.Get("csrf"))) != 1 {
			http.Error(w, "csrf check failed", 403)
			return
		}
		fn(w, r, sess)
	}
}

func (ad *admin) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin", ad.dashboard)
	mux.HandleFunc("GET /admin/mr", ad.mrPage)
	mux.HandleFunc("POST /admin/login", ad.login)
	mux.HandleFunc("POST /admin/logout", ad.guard(ad.logout))
	mux.HandleFunc("POST /admin/pause", ad.guard(ad.pause))
	mux.HandleFunc("POST /admin/agents/toggle", ad.guard(ad.agentToggle))
	mux.HandleFunc("POST /admin/agents/revoke", ad.guard(ad.agentRevoke))
	mux.HandleFunc("POST /admin/agents/new", ad.guard(ad.agentNew))
	mux.HandleFunc("POST /admin/projects/new", ad.guard(ad.projectNew))
	mux.HandleFunc("POST /admin/projects/token", ad.guard(ad.projectToken))
	mux.HandleFunc("POST /admin/projects/delete", ad.guard(ad.projectDelete))
	mux.HandleFunc("POST /admin/mr/approve", ad.guard(ad.mrApprove))
	mux.HandleFunc("POST /admin/mr/reject", ad.guard(ad.mrReject))
	mux.HandleFunc("POST /admin/clients/revoke", ad.guard(ad.clientRevoke))
	mux.HandleFunc("POST /admin/tokens/new", ad.guard(ad.tokenNew))
	mux.HandleFunc("POST /admin/account/password", ad.guard(ad.accPassword))
	mux.HandleFunc("POST /admin/account/username", ad.guard(ad.accUsername))
	mux.HandleFunc("POST /admin/account/totp/start", ad.guard(ad.totpStart))
	mux.HandleFunc("POST /admin/account/totp/enable", ad.guard(ad.totpEnable))
	mux.HandleFunc("POST /admin/account/totp/disable", ad.guard(ad.totpDisable))
}

// ---- pages ----

var pageTmpl = template.Must(template.New("p").Parse(`<!doctype html>
<html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>collabmcp</title>
<style>
body{font:15px system-ui,sans-serif;max-width:64rem;margin:1.5rem auto;padding:0 1rem;color:#111}
h1,h2{margin:.6rem 0}table{border-collapse:collapse;width:100%;margin:.5rem 0}
th,td{border-bottom:1px solid #ddd;padding:.4rem;text-align:left;vertical-align:top;font-size:14px}
input,select,textarea,button{font:inherit;padding:.45rem;margin:.15rem 0;box-sizing:border-box}
input,select,textarea{width:100%}button{cursor:pointer}.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(12rem,1fr));gap:.6rem}
.err{color:#b00020}.ok{color:#0a6b2d}code{background:#f3f3f3;padding:.1rem .3rem;word-break:break-all}
.inline{display:inline}.danger{color:#b00020}.card{border:1px solid #ddd;border-radius:6px;padding:.8rem;margin:.8rem 0}
.banner{background:#fff3cd;border:1px solid #e0c36a;padding:.6rem;border-radius:6px}
pre{background:#f7f7f7;padding:.6rem;overflow:auto;font-size:13px;white-space:pre-wrap;word-break:break-word}
.add{color:#0a6b2d}.del{color:#b00020}
</style></head><body>
<div style="display:flex;justify-content:space-between;align-items:center"><h1>collabmcp</h1>
{{if .CSRF}}<form class="inline" method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Sign out</button></form>{{end}}</div>
{{if .Msg}}<p class="ok">{{.Msg}}</p>{{end}}{{if .Err}}<p class="err">{{.Err}}</p>{{end}}

{{if eq .View "login"}}
<div class="card" style="max-width:22rem"><h2>Sign in</h2>
<form method="post" action="/admin/login" autocomplete="off">
<label>Username<input name="username" autocomplete="username" required autofocus></label>
<label>Password<input type="password" name="password" autocomplete="current-password" required></label>
<label>Authenticator code <small>(only if enabled)</small><input name="totp" inputmode="numeric" maxlength="6"></label>
<button>Sign in</button></form></div>

{{else if eq .View "mr"}}
<p><a href="/admin">&larr; Dashboard</a></p>
<h2>Merge request #{{.MR.ID}}: {{.MR.Project}} / {{.MR.Branch}}</h2>
<p>Author <b>{{.MR.Author}}</b>, status <b>{{.MR.Status}}</b>{{if .MR.Result}} ({{.MR.Result}}){{end}}, head <code>{{.MR.Head}}</code></p>
<div class="card"><b>Summary (written by {{.MR.Author}}, untrusted)</b><pre>{{.MR.Summary}}</pre></div>
<div class="card"><b>Reviews</b> &mdash; peer approvals: {{.Approvals}}, peer change requests: {{.Changes}} (the author's own reviews never count)
<table><tr><th>Reviewer</th><th>Verdict</th><th>Body</th></tr>
{{range .Reviews}}<tr><td>{{.Reviewer}}</td><td>{{.Verdict}}</td><td><pre>{{.Body}}</pre></td></tr>{{else}}<tr><td colspan="3">No reviews yet.</td></tr>{{end}}</table></div>
{{if eq .MR.Status "open"}}
<div class="card"><form method="post" action="/admin/mr/approve"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="id" value="{{.MR.ID}}">
<label><input type="checkbox" name="override" value="1" style="width:auto"> Merge even without a peer approval (or despite change requests)</label><br>
<button>Approve and merge into {{.MR.Base}}</button></form>
<form method="post" action="/admin/mr/reject" style="margin-top:.6rem"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="id" value="{{.MR.ID}}"><button class="danger">Reject</button></form></div>
{{end}}
<h3>Diff against {{.MR.Base}}</h3>
<pre>{{range .Diff}}<span class="{{.Class}}">{{.Text}}</span>
{{end}}</pre>

{{else}}
{{if .TempPW}}<p class="err"><b>Temporary password in use.</b> Change it under Account below now{{if not .TOTPOn}}, then enable an authenticator code{{end}}.</p>{{end}}

<div class="card {{if .Paused}}banner{{end}}"><b>Agents are {{if .Paused}}PAUSED{{else}}running{{end}}.</b> Nothing here ever starts an agent: you start every session yourself.
<form class="inline" method="post" action="/admin/pause"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="paused" value="{{if .Paused}}0{{else}}1{{end}}">
<button>{{if .Paused}}Resume all agents{{else}}Pause all agents{{end}}</button></form></div>

<h2>Agents</h2>
<table><tr><th>Name</th><th>Enabled</th><th></th></tr>
{{range .Agents}}<tr><td>{{.Name}}</td><td>{{if .Enabled}}<span class="ok">yes</span>{{else}}<span class="err">no</span>{{end}}</td>
<td><form class="inline" method="post" action="/admin/agents/toggle"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="name" value="{{.Name}}"><input type="hidden" name="enabled" value="{{if .Enabled}}0{{else}}1{{end}}"><button>{{if .Enabled}}Disable{{else}}Enable{{end}}</button></form>
<form class="inline" method="post" action="/admin/agents/revoke" onsubmit="return confirm('Revoke every token for {{.Name}}?')"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="name" value="{{.Name}}"><button class="danger">Revoke all tokens</button></form></td></tr>{{end}}</table>
<form method="post" action="/admin/agents/new" class="row"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>New agent label<input name="name" pattern="[a-z][a-z0-9-]{0,19}" required></label><button>Add agent</button></form>

<h2>Merge requests</h2>
<table><tr><th>#</th><th>Project</th><th>Branch</th><th>Author</th><th>Status</th><th></th></tr>
{{range .MRs}}<tr><td>{{.ID}}</td><td>{{.Project}}</td><td>{{.Branch}}</td><td>{{.Author}}</td><td>{{.Status}}</td><td><a href="/admin/mr?id={{.ID}}">Review</a></td></tr>
{{else}}<tr><td colspan="6">None.</td></tr>{{end}}</table>

<h2>Projects</h2>
<table><tr><th>Name</th><th>Remote</th><th>Default</th><th>Push token</th><th></th></tr>
{{range .Projects}}<tr><td>{{.Name}}</td><td><code>{{.Remote}}</code></td><td>{{.Branch}}</td><td>{{if .HasToken}}stored (encrypted){{else}}none{{end}}
<form method="post" action="/admin/projects/token"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="name" value="{{.Name}}"><input type="password" name="token" placeholder="new token (blank clears)" autocomplete="off"><button>Set</button></form></td>
<td><form class="inline" method="post" action="/admin/projects/delete" onsubmit="return confirm('Remove {{.Name}} and its local clones?')"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="name" value="{{.Name}}"><button class="danger">Remove</button></form></td></tr>
{{else}}<tr><td colspan="5">No projects yet.</td></tr>{{end}}</table>
<div class="card"><h3>Register project</h3>
<form method="post" action="/admin/projects/new" autocomplete="off"><input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="row"><label>Name<input name="name" required pattern="[a-z0-9][a-z0-9._-]{0,39}"></label>
<label>HTTPS remote URL<input name="remote" placeholder="https://github.com/owner/repo.git" required></label>
<label>Default branch<input name="branch" value="main" required></label></div>
<label>Push token (optional; stored encrypted, never shown again)<input type="password" name="token" autocomplete="off"></label>
<button>Register and clone</button></form></div>

<h2>Tasks (latest 30)</h2>
<table><tr><th>#</th><th>Project</th><th>Title</th><th>Status</th><th>Claimed by</th></tr>
{{range .Tasks}}<tr><td>{{.ID}}</td><td>{{.Project}}</td><td>{{.Title}}</td><td>{{.Status}}</td><td>{{.Claim}}</td></tr>{{else}}<tr><td colspan="5">None.</td></tr>{{end}}</table>

<h2>Locks</h2>
<table><tr><th>Resource</th><th>Owner</th><th>Expires (UTC)</th><th>Reason</th></tr>
{{range .Locks}}<tr><td>{{.Resource}}</td><td>{{.Owner}}</td><td>{{.Expires}}</td><td>{{.Reason}}</td></tr>{{else}}<tr><td colspan="4">None.</td></tr>{{end}}</table>

<h2>Board (latest 30, peer content, untrusted)</h2>
<table><tr><th>#</th><th>Thread</th><th>Author</th><th>Kind</th><th>Body</th></tr>
{{range .Board}}<tr><td>{{.ID}}</td><td>{{.Thread}}</td><td>{{.Author}}</td><td>{{.Kind}}</td><td><pre>{{.Body}}</pre></td></tr>{{else}}<tr><td colspan="5">None.</td></tr>{{end}}</table>

<h2>Account</h2>
<div class="card">
<form method="post" action="/admin/account/password" autocomplete="off"><input type="hidden" name="csrf" value="{{.CSRF}}">
<b>Change password</b> (signed in as <code>{{.AdminUser}}</code>). Signs out other sessions and revokes connected AI clients, which then re-authorise.
<div class="row"><label>Current password<input type="password" name="current" autocomplete="current-password" required></label>
<label>New password (12+ chars)<input type="password" name="new" autocomplete="new-password" minlength="12" required></label>
<label>Repeat<input type="password" name="repeat" autocomplete="new-password" minlength="12" required></label></div>
<button>Change password</button></form>
<hr>
<form method="post" action="/admin/account/username" autocomplete="off"><input type="hidden" name="csrf" value="{{.CSRF}}">
<b>Change username</b>
<div class="row"><label>New username<input name="username" required pattern="[A-Za-z0-9._-]{3,32}"></label>
<label>Current password<input type="password" name="current" required></label></div>
<button>Change username</button></form>
<hr>
<b>Authenticator code (optional): {{if .TOTPOn}}<span class="ok">on</span>{{else}}off{{end}}</b>
{{if .PendingSecret}}
<p>Add this to your authenticator app, then enter a code to switch it on.<br>Secret: <code>{{.PendingSecret}}</code><br>URI: <code>{{.PendingURI}}</code></p>
<form method="post" action="/admin/account/totp/enable"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Code<input name="code" inputmode="numeric" maxlength="6" required></label><button>Enable</button></form>
{{else if .TOTPOn}}
<form method="post" action="/admin/account/totp/disable"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Current password<input type="password" name="current" required></label><button class="danger">Disable</button></form>
{{else}}
<form method="post" action="/admin/account/totp/start"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Set up</button></form>
{{end}}
</div>

<h2>Connected AI clients</h2>
<table><tr><th>Client</th><th>Agent</th><th>Registered</th><th></th></tr>
{{range .Clients}}<tr><td>{{.Name}}<br><small>{{.ID}}</small></td><td>{{.Agent}}</td><td>{{.Created}}</td>
<td><form class="inline" method="post" action="/admin/clients/revoke"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.ID}}"><button class="danger">Revoke</button></form></td></tr>
{{else}}<tr><td colspan="4">None yet. Add <code>{{.Issuer}}/mcp</code> as a custom connector, then pick the agent at the authorise step.</td></tr>{{end}}</table>

<h2>API tokens</h2>
{{if .NewToken}}<div class="card"><b>Copy this token now. It is shown once.</b><br><code>{{.NewToken}}</code><br><br>Or, for clients that only accept a URL (no auth needed):<br><code>{{.Issuer}}/mcp/{{.NewToken}}</code></div>{{end}}
<form method="post" action="/admin/tokens/new"><input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="row"><label>Label<input name="label" placeholder="chatgpt-main" maxlength="40" required pattern="[A-Za-z0-9 ._-]+"></label>
<label>Agent<select name="agent">{{range .Agents}}{{if .Enabled}}<option value="{{.Name}}">{{.Name}}</option>{{end}}{{end}}</select></label></div>
<button>Create token</button></form>
<p><small>Use as <code>Authorization: Bearer TOKEN</code> on <code>{{.Issuer}}/mcp</code>. The token is bound to the chosen agent; revoke it under Connected AI clients.</small></p>

<h2>Audit log (latest 100; kept 90 days)</h2>
<table><tr><th>Time (UTC)</th><th>Actor</th><th>Tool</th><th>Detail</th><th>Result</th></tr>
{{range .Audit}}<tr><td>{{.TS}}</td><td>{{.Actor}}</td><td>{{.Tool}}</td><td><code>{{.Detail}}</code></td><td>{{.Result}}</td></tr>{{end}}</table>
{{end}}
</body></html>`))

type (
	agentRow struct {
		Name    string
		Enabled bool
	}
	projRow struct {
		Name, Remote, Branch string
		HasToken             bool
	}
	clientRow struct{ ID, Name, Agent, Created string }
	auditRow  struct{ TS, Actor, Tool, Detail, Result string }
	mrRow     struct {
		ID                              int64
		Project, Branch, Author, Status string
	}
	taskRow2 struct {
		ID                            int64
		Project, Title, Status, Claim string
	}
	lockRow  struct{ Resource, Owner, Expires, Reason string }
	boardRow struct {
		ID                         int64
		Thread, Author, Kind, Body string
	}
	diffLine struct{ Class, Text string }
	mrDetail struct {
		ID                                            int64
		Project, Branch, Author, Status, Result, Head string
		Summary, Base                                 string
	}
	revRow struct{ Reviewer, Verdict, Body string }
)

type pageData struct {
	TempPW, TOTPOn, Paused       bool
	AdminUser, PendingSecret     string
	PendingURI                   string
	View, CSRF, Msg, Err, Issuer string
	NewToken                     string
	Agents                       []agentRow
	Projects                     []projRow
	MRs                          []mrRow
	Tasks                        []taskRow2
	Locks                        []lockRow
	Board                        []boardRow
	Clients                      []clientRow
	Audit                        []auditRow
	MR                           mrDetail
	Reviews                      []revRow
	Approvals, Changes           int
	Diff                         []diffLine
}

func (ad *admin) render(w http.ResponseWriter, code int, d pageData) {
	secHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = pageTmpl.Execute(w, d)
}

func ts(t int64) string { return time.Unix(t, 0).UTC().Format("2006-01-02 15:04:05") }

func (ad *admin) dashboardData(csrf, msg, errMsg string) pageData {
	d := pageData{View: "dash", CSRF: csrf, Msg: msg, Err: errMsg, Issuer: ad.auth.issuer,
		TempPW: getSetting(ad.db, "pw_temp") == "1", TOTPOn: getSetting(ad.db, "totp_secret") != "",
		AdminUser: getSetting(ad.db, "admin_user"), Paused: ad.app.paused()}
	if sec := getSetting(ad.db, "totp_pending"); sec != "" && !d.TOTPOn {
		d.PendingSecret = sec
		d.PendingURI = fmt.Sprintf("otpauth://totp/collabmcp:%s?secret=%s&issuer=collabmcp", d.AdminUser, sec)
	}
	each := func(q string, f func(rows scanner), args ...any) {
		if rows, err := ad.db.Query(q, args...); err == nil {
			for rows.Next() {
				f(rows)
			}
			rows.Close()
		}
	}
	each(`SELECT name,enabled FROM agents ORDER BY name`, func(r scanner) {
		var x agentRow
		var en int
		if r.Scan(&x.Name, &en) == nil {
			x.Enabled = en == 1
			d.Agents = append(d.Agents, x)
		}
	})
	each(`SELECT name,remote,branch,token_enc<>'' FROM projects ORDER BY name`, func(r scanner) {
		var x projRow
		if r.Scan(&x.Name, &x.Remote, &x.Branch, &x.HasToken) == nil {
			d.Projects = append(d.Projects, x)
		}
	})
	each(`SELECT id,project,branch,author,status FROM merge_requests ORDER BY (status='open') DESC, id DESC LIMIT 30`, func(r scanner) {
		var x mrRow
		if r.Scan(&x.ID, &x.Project, &x.Branch, &x.Author, &x.Status) == nil {
			d.MRs = append(d.MRs, x)
		}
	})
	now := time.Now().Unix()
	each(`SELECT id,project,title,status,assignee,lease_until FROM tasks ORDER BY id DESC LIMIT 30`, func(r scanner) {
		var x taskRow2
		var asg string
		var lease int64
		if r.Scan(&x.ID, &x.Project, &x.Title, &x.Status, &asg, &lease) == nil {
			if asg != "" && lease > now {
				x.Claim = asg
			}
			d.Tasks = append(d.Tasks, x)
		}
	})
	each(`SELECT resource,owner,reason,expires FROM locks WHERE expires>? ORDER BY resource`, func(r scanner) {
		var x lockRow
		var e int64
		if r.Scan(&x.Resource, &x.Owner, &x.Reason, &e) == nil {
			x.Expires = ts(e)
			d.Locks = append(d.Locks, x)
		}
	}, now)
	each(`SELECT id,thread,author,kind,body FROM board ORDER BY id DESC LIMIT 30`, func(r scanner) {
		var x boardRow
		if r.Scan(&x.ID, &x.Thread, &x.Author, &x.Kind, &x.Body) == nil {
			d.Board = append(d.Board, x)
		}
	})
	each(`SELECT c.id,c.name,COALESCE((SELECT agent FROM oauth_tokens t WHERE t.client_id=c.id LIMIT 1),''),c.created FROM oauth_clients c ORDER BY c.created DESC LIMIT 50`, func(r scanner) {
		var x clientRow
		var c int64
		if r.Scan(&x.ID, &x.Name, &x.Agent, &c) == nil {
			x.Created = ts(c)
			d.Clients = append(d.Clients, x)
		}
	})
	each(`SELECT ts,actor,tool,detail,result FROM audit ORDER BY id DESC LIMIT 100`, func(r scanner) {
		var x auditRow
		var t int64
		if r.Scan(&t, &x.Actor, &x.Tool, &x.Detail, &x.Result) == nil {
			x.TS = ts(t)
			d.Audit = append(d.Audit, x)
		}
	})
	return d
}

func (ad *admin) dashboard(w http.ResponseWriter, r *http.Request) {
	csrf, _, ok := ad.session(r)
	if !ok {
		ad.render(w, 200, pageData{View: "login"})
		return
	}
	q := r.URL.Query()
	ad.render(w, 200, ad.dashboardData(csrf, q.Get("m"), q.Get("e")))
}

func (ad *admin) mrPage(w http.ResponseWriter, r *http.Request) {
	csrf, _, ok := ad.session(r)
	if !ok {
		ad.render(w, 200, pageData{View: "login"})
		return
	}
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	var m mrDetail
	m.ID = id
	if ad.db.QueryRow(`SELECT project,branch,author,status,result,head_sha,summary FROM merge_requests WHERE id=?`, id).
		Scan(&m.Project, &m.Branch, &m.Author, &m.Status, &m.Result, &m.Head, &m.Summary) != nil {
		http.NotFound(w, r)
		return
	}
	if p, err := ad.app.loadProject(m.Project); err == nil {
		m.Base = p.Branch
	}
	d := pageData{View: "mr", CSRF: csrf, MR: m}
	d.Approvals, d.Changes = ad.app.peerApproval(id, m.Author)
	if rows, err := ad.db.Query(`SELECT reviewer,verdict,body FROM reviews WHERE mr_id=? ORDER BY id`, id); err == nil {
		for rows.Next() {
			var x revRow
			if rows.Scan(&x.Reviewer, &x.Verdict, &x.Body) == nil {
				d.Reviews = append(d.Reviews, x)
			}
		}
		rows.Close()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	diff, err := ad.app.mrDiff(ctx, id)
	if err != nil {
		d.Err = "Could not compute diff: " + err.Error()
	}
	for _, l := range strings.Split(diff, "\n") {
		c := ""
		switch {
		case strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++"):
			c = "add"
		case strings.HasPrefix(l, "-") && !strings.HasPrefix(l, "---"):
			c = "del"
		}
		d.Diff = append(d.Diff, diffLine{c, l})
	}
	ad.render(w, 200, d)
}

func (ad *admin) login(w http.ResponseWriter, r *http.Request) {
	secHeaders(w)
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	// Origin check: the login POST must come from our own site.
	if o := r.Header.Get("Origin"); o != "" && o != ad.auth.issuer {
		http.Error(w, "bad origin", 403)
		return
	}
	ip := clientIP(r)
	if ad.auth.locked(ip) {
		audit(ad.db, "admin", "admin_login", ip, "locked")
		ad.render(w, 429, pageData{View: "login", Err: "Too many attempts. Try again later."})
		return
	}
	if !ad.auth.credsOK(r.PostForm.Get("username"), r.PostForm.Get("password"), r.PostForm.Get("totp")) {
		ad.auth.recordFail(ip, r.PostForm.Get("username"))
		audit(ad.db, "admin", "admin_login", ip, "failed")
		ad.render(w, 401, pageData{View: "login", Err: "Invalid credentials."})
		return
	}
	ad.auth.recordOK(ip, r.PostForm.Get("username"))
	audit(ad.db, "admin", "admin_login", ip, "ok")
	ad.newSession(w)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (ad *admin) logout(w http.ResponseWriter, r *http.Request, sess string) {
	_, _ = ad.db.Exec(`DELETE FROM sessions WHERE hash=?`, sess)
	http.SetCookie(w, &http.Cookie{Name: "collabmcp_sess", Value: "", Path: "/admin", MaxAge: -1})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func back(w http.ResponseWriter, r *http.Request, msg, e string) {
	u := "/admin"
	if msg != "" {
		u += "?m=" + urlEsc(msg)
	} else if e != "" {
		u += "?e=" + urlEsc(e)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

func urlEsc(s string) string {
	return strings.NewReplacer(" ", "%20", "&", "%26", "#", "%23", "?", "%3F", "+", "%2B", "\n", "%20").Replace(s)
}

// ---- pause, agents ----

func (ad *admin) pause(w http.ResponseWriter, r *http.Request, _ string) {
	v := "0"
	if r.PostForm.Get("paused") == "1" {
		v = "1"
	}
	_ = setSetting(ad.db, "paused", v)
	audit(ad.db, "admin", "pause", v, "ok")
	if v == "1" {
		back(w, r, "All agents paused", "")
	} else {
		back(w, r, "Agents resumed", "")
	}
}

func (ad *admin) agentToggle(w http.ResponseWriter, r *http.Request, _ string) {
	name, en := r.PostForm.Get("name"), 0
	if r.PostForm.Get("enabled") == "1" {
		en = 1
	}
	_, _ = ad.db.Exec(`UPDATE agents SET enabled=? WHERE name=?`, en, name)
	audit(ad.db, "admin", "agent_toggle", name, fmt.Sprint("enabled=", en))
	back(w, r, "Updated "+name, "")
}

func (ad *admin) agentRevoke(w http.ResponseWriter, r *http.Request, _ string) {
	name := r.PostForm.Get("name")
	_, _ = ad.db.Exec(`DELETE FROM oauth_tokens WHERE agent=?`, name)
	audit(ad.db, "admin", "agent_revoke", name, "ok")
	back(w, r, "Revoked all tokens for "+name, "")
}

func (ad *admin) agentNew(w http.ResponseWriter, r *http.Request, _ string) {
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if !reAgent.MatchString(name) {
		back(w, r, "", "Agent label: lowercase letters, digits, hyphen")
		return
	}
	_, _ = ad.db.Exec(`INSERT OR IGNORE INTO agents(name,enabled) VALUES(?,1)`, name)
	audit(ad.db, "admin", "agent_new", name, "ok")
	back(w, r, "Added "+name, "")
}

// ---- projects ----

func (ad *admin) projectNew(w http.ResponseWriter, r *http.Request, _ string) {
	f := r.PostForm
	name, remote, branch, tok := strings.TrimSpace(f.Get("name")), strings.TrimSpace(f.Get("remote")), strings.TrimSpace(f.Get("branch")), strings.TrimSpace(f.Get("token"))
	switch {
	case !reProject.MatchString(name):
		back(w, r, "", "Invalid project name")
		return
	case !validRemote(remote, false):
		back(w, r, "", "Remote must be an https:// URL without embedded credentials")
		return
	case !validBranchName(branch):
		back(w, r, "", "Invalid default branch")
		return
	case len(tok) > 500:
		back(w, r, "", "Token too long")
		return
	}
	enc := ""
	if tok != "" {
		var err error
		if enc, err = vault.Seal(tok); err != nil {
			back(w, r, "", "Encryption failed")
			return
		}
	}
	if _, err := ad.db.Exec(`INSERT INTO projects(name,remote,branch,token_enc,created) VALUES(?,?,?,?,?)`, name, remote, branch, enc, time.Now().Unix()); err != nil {
		back(w, r, "", "A project with that name already exists")
		return
	}
	audit(ad.db, "admin", "project_new", name+" "+remote, "ok")
	p, _ := ad.app.loadProject(name)
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	if err := ad.app.git.ensureRepo(ctx, p); err != nil {
		back(w, r, "", "Registered, but clone failed: "+err.Error())
		return
	}
	back(w, r, "Registered and cloned "+name, "")
}

func (ad *admin) projectToken(w http.ResponseWriter, r *http.Request, _ string) {
	name, tok := r.PostForm.Get("name"), strings.TrimSpace(r.PostForm.Get("token"))
	enc := ""
	if tok != "" {
		if len(tok) > 500 {
			back(w, r, "", "Token too long")
			return
		}
		var err error
		if enc, err = vault.Seal(tok); err != nil {
			back(w, r, "", "Encryption failed")
			return
		}
	}
	_, _ = ad.db.Exec(`UPDATE projects SET token_enc=? WHERE name=?`, enc, name)
	audit(ad.db, "admin", "project_token", name, map[bool]string{true: "set", false: "cleared"}[tok != ""])
	back(w, r, "Token updated for "+name, "")
}

func (ad *admin) projectDelete(w http.ResponseWriter, r *http.Request, _ string) {
	name := r.PostForm.Get("name")
	if !reProject.MatchString(name) {
		back(w, r, "", "Invalid name")
		return
	}
	_, _ = ad.db.Exec(`DELETE FROM projects WHERE name=?`, name)
	removeAll(ad.app.git.repoDir(name))
	removeAll(ad.app.git.workRoot(name))
	audit(ad.db, "admin", "project_delete", name, "ok")
	back(w, r, "Removed "+name, "")
}

// ---- merge requests: the only path to a merge ----

func (ad *admin) mrApprove(w http.ResponseWriter, r *http.Request, _ string) {
	id, _ := strconv.ParseInt(r.PostForm.Get("id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	err := ad.app.approveMR(ctx, id, r.PostForm.Get("override") == "1")
	if err != nil {
		audit(ad.db, "admin", "mr_approve", fmt.Sprint(id), "error: "+err.Error())
		back(w, r, "", fmt.Sprintf("Request %d not merged: %v", id, err))
		return
	}
	audit(ad.db, "admin", "mr_approve", fmt.Sprint(id), "merged")
	back(w, r, fmt.Sprintf("Request %d merged", id), "")
}

func (ad *admin) mrReject(w http.ResponseWriter, r *http.Request, _ string) {
	id, _ := strconv.ParseInt(r.PostForm.Get("id"), 10, 64)
	if err := ad.app.rejectMR(id); err != nil {
		back(w, r, "", err.Error())
		return
	}
	audit(ad.db, "admin", "mr_reject", fmt.Sprint(id), "ok")
	back(w, r, fmt.Sprintf("Request %d rejected", id), "")
}

// ---- clients and tokens ----

func (ad *admin) clientRevoke(w http.ResponseWriter, r *http.Request, _ string) {
	id := r.PostForm.Get("id")
	_, _ = ad.db.Exec(`DELETE FROM oauth_tokens WHERE client_id=?`, id)
	_, _ = ad.db.Exec(`DELETE FROM oauth_clients WHERE id=?`, id)
	audit(ad.db, "admin", "client_revoke", id, "ok")
	back(w, r, "Client revoked", "")
}

func (ad *admin) tokenNew(w http.ResponseWriter, r *http.Request, _ string) {
	csrf, _, _ := ad.session(r)
	label, agent := strings.TrimSpace(r.PostForm.Get("label")), r.PostForm.Get("agent")
	if !reLabel.MatchString(label) {
		back(w, r, "", "Label: letters, digits, space . _ - (max 40)")
		return
	}
	if !ad.auth.agentOK(agent) {
		back(w, r, "", "Choose an enabled agent")
		return
	}
	id := randToken(16)
	tok := "collab_" + randToken(32)
	_, e1 := ad.db.Exec(`INSERT INTO oauth_clients(id,name,redirect_uris,created) VALUES(?,?,?,?)`, id, "API token: "+label, "[]", time.Now().Unix())
	_, e2 := ad.db.Exec(`INSERT INTO oauth_tokens(hash,kind,client_id,agent,expires) VALUES(?,?,?,?,?)`, hashToken(tok), "access", id, agent, int64(4102444800))
	if e1 != nil || e2 != nil {
		back(w, r, "", "Could not create token")
		return
	}
	audit(ad.db, "admin", "token_new", label+" agent="+agent, "ok")
	d := ad.dashboardData(csrf, "Token created for "+agent, "")
	d.NewToken = tok
	w.Header().Set("Cache-Control", "no-store")
	ad.render(w, 200, d)
}

// ---- account ----

func (ad *admin) verifyCurrent(r *http.Request) bool {
	ip := clientIP(r)
	if ad.auth.locked(ip) {
		return false
	}
	ok := bcrypt.CompareHashAndPassword([]byte(getSetting(ad.db, "pw_hash")), []byte(r.PostForm.Get("current"))) == nil
	if !ok {
		ad.auth.recordFail(ip, getSetting(ad.db, "admin_user"))
		audit(ad.db, "admin", "account", ip, "current password wrong")
	}
	return ok
}

func (ad *admin) accPassword(w http.ResponseWriter, r *http.Request, sess string) {
	if !ad.verifyCurrent(r) {
		back(w, r, "", "Current password wrong (or too many attempts)")
		return
	}
	nw := r.PostForm.Get("new")
	switch {
	case len(nw) < 12:
		back(w, r, "", "New password must be at least 12 characters")
		return
	case len(nw) > 72:
		back(w, r, "", "New password too long (max 72 bytes)")
		return
	case nw != r.PostForm.Get("repeat"):
		back(w, r, "", "Passwords differ")
		return
	case nw == r.PostForm.Get("current"):
		back(w, r, "", "New password must differ")
		return
	}
	h, err := bcrypt.GenerateFromPassword([]byte(nw), 12)
	if err != nil {
		back(w, r, "", "Could not hash password")
		return
	}
	_ = setSetting(ad.db, "pw_hash", string(h))
	_ = setSetting(ad.db, "pw_temp", "0")
	_, _ = ad.db.Exec(`DELETE FROM sessions WHERE hash<>?`, sess)
	_, _ = ad.db.Exec(`DELETE FROM oauth_tokens`)
	audit(ad.db, "admin", "account", "", "password changed; other sessions and AI clients revoked")
	back(w, r, "Password changed. Other sessions and AI clients were signed out.", "")
}

func (ad *admin) accUsername(w http.ResponseWriter, r *http.Request, _ string) {
	if !ad.verifyCurrent(r) {
		back(w, r, "", "Current password wrong (or too many attempts)")
		return
	}
	u := strings.TrimSpace(r.PostForm.Get("username"))
	if !regexp.MustCompile(`^[A-Za-z0-9._-]{3,32}$`).MatchString(u) {
		back(w, r, "", "Username: 3-32 letters, digits, . _ -")
		return
	}
	_ = setSetting(ad.db, "admin_user", u)
	audit(ad.db, "admin", "account", u, "username changed")
	back(w, r, "Username changed", "")
}

func (ad *admin) totpStart(w http.ResponseWriter, r *http.Request, _ string) {
	k, err := totp.Generate(totp.GenerateOpts{Issuer: "collabmcp", AccountName: getSetting(ad.db, "admin_user")})
	if err != nil {
		back(w, r, "", "Could not generate secret")
		return
	}
	_ = setSetting(ad.db, "totp_pending", k.Secret())
	back(w, r, "Scan or enter the secret, then confirm with a code", "")
}

func (ad *admin) totpEnable(w http.ResponseWriter, r *http.Request, _ string) {
	sec := getSetting(ad.db, "totp_pending")
	if sec == "" || !totp.Validate(strings.TrimSpace(r.PostForm.Get("code")), sec) {
		back(w, r, "", "Code did not match; try again")
		return
	}
	_ = setSetting(ad.db, "totp_secret", sec)
	_ = setSetting(ad.db, "totp_pending", "")
	audit(ad.db, "admin", "account", "", "TOTP enabled")
	back(w, r, "Authenticator code enabled", "")
}

func (ad *admin) totpDisable(w http.ResponseWriter, r *http.Request, _ string) {
	if !ad.verifyCurrent(r) {
		back(w, r, "", "Current password wrong (or too many attempts)")
		return
	}
	_ = setSetting(ad.db, "totp_secret", "")
	_ = setSetting(ad.db, "totp_pending", "")
	audit(ad.db, "admin", "account", "", "TOTP disabled")
	back(w, r, "Authenticator code disabled", "")
}
