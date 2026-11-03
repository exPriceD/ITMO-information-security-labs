package main

import (
	"database/sql"
	"golang.org/x/crypto/bcrypt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

var loginPattern = regexp.MustCompile(`^[a-zA-Z0-9_]{1,32}$`)

func (a *app) takeAttempt(ip, login string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	// Окно не продлевается новыми попытками. Состояние очищается после истечения.
	for k, v := range a.attempts {
		if !now.Before(v.Until) {
			delete(a.attempts, k)
		}
	}
	keys := []string{"ip:" + ip, "pair:" + ip + ":" + login}
	limits := []int{30, 5}
	for i, k := range keys {
		if a.attempts[k].Count >= limits[i] {
			return false
		}
	}
	for _, k := range keys {
		v := a.attempts[k]
		if v.Count == 0 {
			v.Until = now.Add(time.Minute)
		}
		v.Count++
		a.attempts[k] = v
	}
	return true
}
func (a *app) secureLogin(w http.ResponseWriter, r *http.Request) {
	login, password := r.FormValue("login"), r.FormValue("password")
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	// FIX-03: максимум 5 попыток на пару IP+логин и 30 на IP за минуту.
	if !a.takeAttempt(ip, login) {
		w.Header().Set("Retry-After", strconv.Itoa(60))
		a.render(w, 429, "Слишком много попыток. Повторите через минуту.", "")
		return
	}
	// Дополнительная проверка формата. SQL защищён параметрами независимо от неё.
	if !loginPattern.MatchString(login) || len(password) == 0 || len(password) > 72 {
		a.render(w, 401, "Неверный логин или пароль", "")
		return
	}
	var user, hash string
	// FIX-01: SQL-команда постоянна, логин передаётся отдельным параметром.
	err := a.db.QueryRow("SELECT login, password FROM users WHERE login = ?", login).Scan(&user, &hash)
	if err != nil && err != sql.ErrNoRows {
		a.render(w, 500, "Внутренняя ошибка", "")
		return
	}
	target := []byte(hash)
	if err == sql.ErrNoRows {
		target = a.dummy
	}
	// FIX-02: проверка bcrypt; для отсутствующего логина тоже считаем bcrypt.
	match := bcrypt.CompareHashAndPassword(target, []byte(password)) == nil
	if err == sql.ErrNoRows || !match {
		// FIX-04: одинаковые текст и HTTP-статус.
		a.render(w, 401, "Неверный логин или пароль", "")
		return
	}
	a.issue(w, r, user)
}
