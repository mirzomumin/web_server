package main

import (
	"net/http"
	"github.com/gorilla/mux"
	"encoding/json"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"github.com/golang-jwt/jwt"
	"time"
)

const SECRET_KEY = "MY_SECRET_KEY"

type User struct {
	Id int `json:"id"`
	Login string `json:"login,omitempty"`
	Name string `json:"name,omitempty"`
	Age int `json:"age,omitempty"`
	Password string `json:"password,omitempty"`
}

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
	var user User
	var errors []string
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		errors = append(errors, err.Error())
	}
	json.Unmarshal(reqBody, &user)

	db, err := sql.Open("sqlite3", "serverDb.sqlite3")
	if err != nil {
		errors = append(errors, err.Error())
	}
	var userId int
	var hashedPassword string
	row := db.QueryRow("SELECT id, password FROM users WHERE login=?", user.Login)
	err = row.Scan(&userId, &hashedPassword)
	if err != nil {
		errors = append(errors, err.Error())
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(hashedPassword), []byte(user.Password))
	if err != nil {
		errors = append(errors, err.Error())
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.MapClaims{
			"user_id": userId,
			"login":  user.Login,
			"exp": time.Now().Add(1 * time.Minute).Unix(),
		})
	tokenString, err := token.SignedString([]byte(SECRET_KEY))
	if err != nil {
		errors = append(errors, err.Error())
	}

	cookie := http.Cookie{
		Name: "SESSTOKEN",
		Value: tokenString,
		Expires: time.Now().Add(1 * time.Minute),
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

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/user/register", SignUp).Methods("POST")
	router.HandleFunc("/user/login", SignIn).Methods("POST")
	http.Handle("/", router)
	http.ListenAndServe("localhost:8000", nil)
}