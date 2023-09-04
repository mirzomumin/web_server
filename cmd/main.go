package main

import (
	"net/http"
	"github.com/mirzomumin/web_server/pkg/middleware"
	"github.com/mirzomumin/web_server/internal/services"
	"github.com/gorilla/mux"
)

func main() {
	router := mux.NewRouter()

	// Subrouter for another handlers
	myRouter := router.Methods(
		http.MethodPost,
		http.MethodPut,
		http.MethodGet,
		http.MethodDelete,
	).PathPrefix("/user").Subrouter()
	myRouter.HandleFunc("/phone", services.ListAddContact).Methods("POST", "GET")
	myRouter.HandleFunc("/phone/{id:[0-9]+}", services.UpdateRemoveContact).Methods("PUT", "DELETE")
	myRouter.HandleFunc("/{name:[a-zA-Z]+}", services.GetUser).Methods("GET")
	myRouter.Use(middleware.AuthMiddleware)

	// Subrouter for user register and login
	authRouter := router.Methods(
		http.MethodPost,
	).PathPrefix("/user").Subrouter()
	authRouter.HandleFunc("/register", services.SignUp).Methods("POST")
	authRouter.HandleFunc("/login", services.SignIn).Methods("POST")

	http.Handle("/", router)
	http.ListenAndServe("localhost:8000", router)
}