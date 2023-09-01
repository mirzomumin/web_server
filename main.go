package main

import (
	"net/http"
	"github.com/gorilla/mux"
	"encoding/json"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Id int `json:"id"`
	Login string `json:"login,omitempty"`
	Name string `json:"name,omitempty"`
	Age int `json:"age,omitempty"`
	Password string `json:"password,omitempty"`
}

func SignUpUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	r.ParseForm()
	var errorList []string

	login := r.FormValue("login")
	name := r.FormValue("name")
	age := r.FormValue("age")
	password := r.FormValue("password")

	db, err := sql.Open("sqlite3", "serverDb.sqlite3")
	if err != nil {
		errorList = append(errorList, err.Error())
	}
	defer db.Close()

	// Hashing the password
	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(password), bcrypt.DefaultCost)
	if err != nil {
		errorList = append(errorList, err.Error())
	}

	stmt, err := db.Prepare(
		"INSERT INTO users(login, name, age, password) VALUES(?,?,?,?)")
	if err != nil {
		errorList = append(errorList, err.Error())
	}
	_, err = stmt.Exec(login, name, age, string(hashedPassword))
	if err != nil {
		errorList = append(errorList, err.Error())
	}
	if errorList != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(
			map[string][]string{"errors": errorList})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(
		map[string]string{"message": "User is successfully created!"})
	return
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/user/register", SignUpUser).Methods("POST")
	http.Handle("/", router)
	http.ListenAndServe("localhost:8000", nil)
}