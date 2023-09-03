package repository

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

func SignUpUser(db *sql.DB) {
	db, err := sql.Open("sqlite3", "serverDb.sqlite3")
	if err != nil {
		errors = append(errors, err.Error())
	}
	defer db.Close()

	_, err = db.Exec(
		"INSERT INTO users(login, name, age, password) VALUES(?,?,?,?)",
		login, name, age, string(hashedPassword))
}