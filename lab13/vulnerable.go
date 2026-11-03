package main

import (
	"database/sql"
	"net/http"
)

func (a *app) vulnerableLogin(w http.ResponseWriter, r *http.Request) {
	login, password := r.FormValue("login"), r.FormValue("password")
	// VULN-01: пользовательский ввод становится частью SQL.
	query := "SELECT login FROM users WHERE login = '" + login + "' AND password = '" + password + "'"
	var user string
	err := a.db.QueryRow(query).Scan(&user)
	if err == nil {
		a.issue(w, r, user)
		return
	}
	if err != sql.ErrNoRows {
		a.render(w, 400, "Ошибка запроса", "")
		return
	}
	// VULN-04: разные сообщения раскрывают существование учётной записи.
	var exists int
	if e := a.db.QueryRow("SELECT 1 FROM users WHERE login = ?", login).Scan(&exists); e == nil {
		a.render(w, 401, "Неверный пароль", "")
	} else {
		a.render(w, 401, "Пользователь не найден", "")
	}
	// VULN-03: счётчика попыток и временной блокировки нет.
}
