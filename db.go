package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
  name TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS oauth_clients (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, redirect_uris TEXT NOT NULL, created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_codes (
  hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
  challenge TEXT NOT NULL, agent TEXT NOT NULL DEFAULT '', expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
  hash TEXT PRIMARY KEY, kind TEXT NOT NULL, client_id TEXT NOT NULL,
  agent TEXT NOT NULL DEFAULT '', expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, actor TEXT NOT NULL,
  tool TEXT NOT NULL, detail TEXT NOT NULL, result TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
CREATE TABLE IF NOT EXISTS projects (
  name TEXT PRIMARY KEY, remote TEXT NOT NULL, branch TEXT NOT NULL DEFAULT 'main',
  token_enc TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS board (
  id INTEGER PRIMARY KEY AUTOINCREMENT, thread TEXT NOT NULL, author TEXT NOT NULL,
  kind TEXT NOT NULL, body TEXT NOT NULL, ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS board_thread ON board(thread, id);
CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'todo', author TEXT NOT NULL, assignee TEXT NOT NULL DEFAULT '',
  lease_until INTEGER NOT NULL DEFAULT 0, depends_on TEXT NOT NULL DEFAULT '[]',
  created INTEGER NOT NULL, updated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS task_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL, author TEXT NOT NULL,
  status TEXT NOT NULL, note TEXT NOT NULL, ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS locks (
  resource TEXT PRIMARY KEY, owner TEXT NOT NULL, reason TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS merge_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL, author TEXT NOT NULL,
  branch TEXT NOT NULL, head_sha TEXT NOT NULL, summary TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','merged','rejected','failed')),
  result TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL, decided INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT, mr_id INTEGER NOT NULL, reviewer TEXT NOT NULL,
  verdict TEXT NOT NULL, body TEXT NOT NULL, ts INTEGER NOT NULL
);
`

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	for _, n := range []string{"claude", "chatgpt"} {
		if _, err := db.Exec(`INSERT OR IGNORE INTO agents(name,enabled) VALUES(?,1)`, n); err != nil {
			return nil, err
		}
	}
	return db, nil
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func getSetting(db *sql.DB, k string) string {
	var v string
	_ = db.QueryRow(`SELECT v FROM settings WHERE k=?`, k).Scan(&v)
	return v
}

func setSetting(db *sql.DB, k, v string) error {
	_, err := db.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

func audit(db *sql.DB, actor, tool, detail, result string) {
	if len(detail) > 2000 {
		detail = detail[:2000] + "…"
	}
	if len(result) > 500 {
		result = result[:500] + "…"
	}
	_, _ = db.Exec(`INSERT INTO audit(ts,actor,tool,detail,result) VALUES(?,?,?,?,?)`,
		time.Now().Unix(), actor, tool, detail, result)
}

// auditRetention is how long audit rows are kept.
const auditRetention = 90 * 24 * time.Hour

func purgeExpired(db *sql.DB) {
	now := time.Now().Unix()
	_, _ = db.Exec(`DELETE FROM oauth_codes WHERE expires < ?`, now)
	_, _ = db.Exec(`DELETE FROM oauth_tokens WHERE expires < ?`, now)
	_, _ = db.Exec(`DELETE FROM sessions WHERE expires < ?`, now)
	_, _ = db.Exec(`DELETE FROM locks WHERE expires < ?`, now)
	_, _ = db.Exec(`DELETE FROM audit WHERE ts < ?`, now-int64(auditRetention.Seconds()))
}

// scanner is satisfied by *sql.Rows.
type scanner interface{ Scan(dest ...any) error }

func removeAll(p string) { _ = os.RemoveAll(p) }
