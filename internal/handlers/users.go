package handlers

import (
	"database/sql"
	"encoding/json"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"github.com/mirzomumin/web_server/internal/domains"
	"github.com/mirzomumin/web_server/pkg/auth"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
	"time"
)

// Sign Up user function
func SignUp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	r.ParseForm()
	var errors []string

	login := r.FormValue("login")
	name := r.FormValue("name")
	age := r.FormValue("age")
	password := r.FormValue("password")

	db, err := sql.Open("sqlite3", "serverDb.sqlite3")
	if err != nil {
		errors = append(errors, err.Error())
	}
	defer db.Close()

	// Hashing the password
	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(password), bcrypt.DefaultCost)
	if err != nil {
		errors = append(errors, err.Error())
	}

	_, err = db.Exec(
		"INSERT INTO users(login, name, age, password) VALUES(?,?,?,?)",
		login, name, age, string(hashedPassword))
	if err != nil {
		errors = append(errors, err.Error())
	}
	if errors != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(
			map[string][]string{"errors": errors})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(
		map[string]string{"message": "User is successfully created!"})
}

// Sign In user function
func SignIn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user domains.User
	var errors []string
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		errors = append(errors, err.Error())
	}
	err = json.Unmarshal(reqBody, &user)
	if err != nil {
		errors = append(errors, err.Error())
	}

	db, err := sql.Open("sqlite3", "serverDb.sqlite3")
	defer db.Close()
	if err != nil {
		errors = append(errors, err.Error())
	}

	var hashedPassword string
	row := db.QueryRow("SELECT id, password FROM users WHERE login=?", user.Login)
	err = row.Scan(&user.Id, &hashedPassword)
	if err != nil {
		errors = append(errors, err.Error())
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(hashedPassword), []byte(user.Password))
	if err != nil {
		errors = append(errors, err.Error())
	}

	token, err := auth.GenerateJWT(&user)
	if err != nil {
		errors = append(errors, err.Error())
	}

	cookie := http.Cookie{
		Name:     "SESSTOKEN",
		Value:    token,
		Expires:  time.Now().Add(1 * time.Minute),
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	if errors != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(
			map[string][]string{"errors": errors})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(
		map[string]string{"message": "success"})
}

// Get user
func GetUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	name := params["name"]
	var user domains.User
	var errors []string

	db, err := sql.Open("sqlite3", "serverDb.sqlite3")
	if err != nil {
		errors = append(errors, err.Error())
	}
	defer db.Close()
	row := db.QueryRow(
		"SELECT id, name, age FROM users WHERE name=?", name)
	err = row.Scan(&user.Id, &user.Name, &user.Age)
	if err != nil {
		errors = append(errors, err.Error())
	}

	jsonData, err := json.Marshal(user)
	if err != nil {
		errors = append(errors, err.Error())
	}

	if errors != nil {
		json.NewEncoder(w).Encode(
			map[string][]string{"error": errors})
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}
