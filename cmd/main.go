package main

import (
	"net/http"
	"github.com/mirzomumin/web_server/pkg/middleware"
	"github.com/mirzomumin/web_server/internal/handlers"
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
	myRouter.HandleFunc("/phone", handlers.ListAddContact).Methods("POST", "GET")
	myRouter.HandleFunc("/phone/{id:[0-9]+}", handlers.UpdateRemoveContact).Methods("PUT", "DELETE")
	myRouter.HandleFunc("/{name:[a-zA-Z]+}", handlers.GetUser).Methods("GET")
	myRouter.Use(middleware.AuthMiddleware)

	// Subrouter for user register and login
	authRouter := router.Methods(
		http.MethodPost,
	).PathPrefix("/user").Subrouter()
	authRouter.HandleFunc("/register", handlers.SignUp).Methods("POST")
	authRouter.HandleFunc("/login", handlers.SignIn).Methods("POST")

	http.Handle("/", router)
	http.ListenAndServe("localhost:8000", router)
}