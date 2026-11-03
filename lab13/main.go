package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type session struct {
	User    string
	Expires time.Time
}
type attempt struct {
	Count int
	Until time.Time
}
type app struct {
	db       *sql.DB
	secure   bool
	mu       sync.Mutex
	sessions map[string]session
	attempts map[string]attempt
	dummy    []byte
}

var page = template.Must(template.New("page").Parse(`<!doctype html><html lang="ru"><meta charset="utf-8"><title>Аудит приложения</title><style>
body{font:18px Arial;background:#f1f3f5;color:#20252b;margin:0}main{max-width:680px;margin:55px auto;background:white;padding:34px;border:1px solid #cbd0d5;border-radius:8px}h1{font-size:27px}label{display:block;margin-top:18px}input{display:block;padding:10px;width:95%;font-size:18px;border:1px solid #969da4;margin-top:7px}button{background:#264d73;color:white;border:0;padding:12px 25px;font-size:18px;margin-top:24px}small{color:#59636e}.result{padding:15px;background:#eef2f6;margin:20px 0;white-space:pre-wrap}a{color:#264d73}</style><main><small>Практическая работа №13 · {{.Mode}}</small><h1>Форма входа</h1>{{if .Message}}<div class="result">{{.Message}}</div>{{end}}{{if .User}}<p>Вход выполнен: <strong>{{.User}}</strong></p><p>Личный кабинет доступен.</p><form method="post" action="/logout"><button>Выйти</button></form>{{else}}<form action="/login" method="post"><label>Логин<input name="login" autocomplete="off"></label><label>Пароль<input name="password" type="password" autocomplete="off"></label><button>Войти</button></form>{{end}}</main></html>`))

func (a *app) render(w http.ResponseWriter, status int, message, user string) {
	mode := "Уязвимая версия"
	if a.secure {
		mode = "Защищённая версия"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'")
	w.WriteHeader(status)
	if err := page.Execute(w, map[string]string{"Mode": mode, "Message": message, "User": user}); err != nil {
		log.Print(err)
	}
}
func newApp(path string, secure bool) (*app, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, login TEXT UNIQUE NOT NULL, password TEXT NOT NULL)"); err != nil {
		return nil, err
	}
	a := &app{db: db, secure: secure, sessions: map[string]session{}, attempts: map[string]attempt{}}
	a.dummy, err = bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), 12)
	if err != nil {
		return nil, err
	}
	var count int
	if err = db.QueryRow("SELECT count(*) FROM users").Scan(&count); err != nil {
		return nil, err
	}
	if count == 0 {
		// Учебные учётные записи. Это тестовые данные, не секреты развёртывания.
		for _, u := range [][2]string{{"admin", "Admin!2026"}, {"student", "Study!2026"}} {
			value := u[1]
			if secure {
				hash, e := bcrypt.GenerateFromPassword([]byte(value), 12)
				if e != nil {
					return nil, e
				}
				value = string(hash)
			}
			// VULN-02: в уязвимом режиме value содержит открытый пароль.
			if _, err = db.Exec("INSERT INTO users(login,password) VALUES(?,?)", u[0], value); err != nil {
				return nil, err
			}
		}
	}
	return a, nil
}
func (a *app) issue(w http.ResponseWriter, r *http.Request, user string) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		a.render(w, 500, "Внутренняя ошибка", "")
		return
	}
	id := hex.EncodeToString(token)
	a.mu.Lock()
	a.sessions[id] = session{user, time.Now().Add(30 * time.Minute)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 1800})
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}
func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		a.render(w, 200, "", "")
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil {
			a.render(w, 400, "Некорректный запрос", "")
			return
		}
		if a.secure {
			a.secureLogin(w, r)
		} else {
			a.vulnerableLogin(w, r)
		}
	})
	mux.HandleFunc("GET /profile", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sid")
		if err != nil {
			a.render(w, 401, "Требуется вход", "")
			return
		}
		a.mu.Lock()
		s, ok := a.sessions[c.Value]
		if ok && time.Now().After(s.Expires) {
			delete(a.sessions, c.Value)
			ok = false
		}
		a.mu.Unlock()
		if !ok {
			a.render(w, 401, "Требуется вход", "")
			return
		}
		a.render(w, 200, "", s.User)
	})
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		if c, e := r.Cookie("sid"); e == nil {
			a.mu.Lock()
			delete(a.sessions, c.Value)
			a.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/", 303)
	})
	return mux
}
func main() {
	mode := flag.String("mode", "secure", "vulnerable или secure")
	addr := flag.String("addr", "127.0.0.1:8081", "адрес сервера")
	dbpath := flag.String("db", "", "файл SQLite")
	flag.Parse()
	if *mode != "secure" && *mode != "vulnerable" {
		log.Fatal("неизвестный режим")
	}
	if *dbpath == "" {
		*dbpath = *mode + ".db"
	}
	a, err := newApp(*dbpath, *mode == "secure")
	if err != nil {
		log.Fatal(err)
	}
	defer a.db.Close()
	fmt.Fprintf(os.Stdout, "mode=%s http://%s database=%s\n", *mode, *addr, *dbpath)
	srv := &http.Server{Addr: *addr, Handler: a.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
