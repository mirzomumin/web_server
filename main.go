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
	"github.com/mirzomumin/web_server/middleware"
)

const SECRET_KEY = "MY_SECRET_KEY"

type User struct {
	Id int `json:"id"`
	Login string `json:"login,omitempty"`
	Name string `json:"name,omitempty"`
	Age int `json:"age,omitempty"`
	Password string `json:"password,omitempty"`
}

type Contact struct {
	Id int `json:"id"`
	Phone string `json:"phone"`
	Description string `json:"description"`
	IsFax bool `json:"is_fax"`
	UserId int `json:"user_id"`
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
	err = json.Unmarshal(reqBody, &user)
	if err != nil {
		errors = append(errors, err.Error())
	}

	db, err := sql.Open("sqlite3", "serverDb.sqlite3")
	defer db.Close()
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

// Get user
func GetUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	name := params["name"]
	var user User
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

// Add new contact or return all exsiting contacts
func ListAddContact(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var errors []string
	db, err := sql.Open("sqlite3", "serverDb.sqlite3")
	if err != nil {
		errors = append(errors, err.Error())
	}
	defer db.Close()
	if r.Method == "POST" {
		var contact Contact
		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			errors = append(errors, err.Error())
		}
		json.Unmarshal(reqBody, &contact)

		props, _ := r.Context().Value("props").(jwt.MapClaims)
		contact.UserId = int(props["user_id"].(float64))

		_, err = db.Exec(
			"INSERT INTO contacts (phone, description, is_fax, user_id) VALUES (?,?,?,?)",
			contact.Phone, contact.Description, contact.IsFax, contact.UserId)
		if err != nil {
			errors = append(errors, err.Error())
		}

		if errors != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(
				map[string][]string{"error": errors})
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(
			map[string]string{"message": "Contact is successfully added!"})
	} else {
		q := r.URL.Query().Get("q")
		contacts := []Contact{}

		rows, err := db.Query("SELECT id, user_id, phone, description, is_fax FROM contacts WHERE phone LIKE '%' || ? || '%'", q)
		if err != nil {
			errors = append(errors, err.Error())
		}
		for rows.Next() {
			var contact Contact
			rows.Scan(&contact.Id, &contact.UserId, &contact.Phone,
				&contact.Description, &contact.IsFax)
			contacts = append(contacts, contact)
		}

		jsonData, err := json.Marshal(contacts)
		if err != nil {
			errors = append(errors, err.Error())
		}

		if errors != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(
				map[string][]string{"error": errors})
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(jsonData)
	}
}

// Update or remove specific contact
func UpdateRemoveContact(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	var errors []string
	db, err := sql.Open("sqlite3", "serverDb.sqlite3")
	if err != nil {
		errors = append(errors, err.Error())
	}
	if r.Method == "PUT" {
		var contact Contact
		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			errors = append(errors, err.Error())
		}

		row := db.QueryRow(
			"SELECT phone, description, is_fax, user_id FROM contacts WHERE id=?",
			params["id"],
		)
		err = row.Scan(&contact.Phone, &contact.Description, &contact.IsFax, &contact.UserId)
		if err != nil {
			errors = append(errors, err.Error())
		}

		err = json.Unmarshal(reqBody, &contact)
		if err != nil {
			errors = append(errors, err.Error())
		}

		props, _ := r.Context().Value("props").(jwt.MapClaims)
		contact.UserId = int(props["user_id"].(float64))

		_, err = db.Exec("UPDATE contacts SET phone=?, description=?, is_fax=?, user_id=? WHERE id=?", contact.Phone, contact.Description, contact.IsFax, contact.UserId, params["id"])
		if err != nil {
			errors = append(errors, err.Error())
		}

		if errors != nil {
			json.NewEncoder(w).Encode(
				map[string][]string{"error": errors})
			return
		}

		json.NewEncoder(w).Encode(
			map[string]string{"message": "success"})
	} else {
		_, err = db.Exec("DELETE FROM contacts WHERE id=?", params["id"])
		if err != nil {
			errors = append(errors, err.Error())
		}

		if errors != nil {
			json.NewEncoder(w).Encode(
				map[string][]string{"error": errors})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}



func main() {
	router := mux.NewRouter()

	// Subrouter for another handlers
	myRouter := router.Methods(
		http.MethodPost,
		http.MethodPut,
		http.MethodGet,
		http.MethodDelete,
	).PathPrefix("/user").Subrouter()
	myRouter.HandleFunc("/phone", ListAddContact).Methods("POST", "GET")
	myRouter.HandleFunc("/phone/{id:[0-9]+}", UpdateRemoveContact).Methods("PUT", "DELETE")
	myRouter.HandleFunc("/{name:[a-zA-Z]+}", GetUser).Methods("GET")
	myRouter.Use(middleware.AuthMiddleware)

	// Subrouter for user register and login
	authRouter := router.Methods(
		http.MethodPost,
	).PathPrefix("/user").Subrouter()
	authRouter.HandleFunc("/register", SignUp).Methods("POST")
	authRouter.HandleFunc("/login", SignIn).Methods("POST")

	http.Handle("/", router)
	http.ListenAndServe("localhost:8000", nil)
}