package handlers

import (
	"net/http"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"io/ioutil"
	"github.com/golang-jwt/jwt"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/mirzomumin/web_server/internal/domains"
)

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
		var contact domains.Contact
		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			errors = append(errors, err.Error())
		}
		json.Unmarshal(reqBody, &contact)

		if len(contact.Phone) > 12 {
			err := "phone field max length is 12"
			errors = append(errors, err)
		}

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
		contacts := []domains.Contact{}

		rows, err := db.Query("SELECT id, user_id, phone, description, is_fax FROM contacts WHERE phone LIKE '%' || ? || '%'", q)
		if err != nil {
			errors = append(errors, err.Error())
		}
		for rows.Next() {
			var contact domains.Contact
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
		var contact domains.Contact
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
