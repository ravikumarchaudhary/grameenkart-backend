package main

import (
	"fmt"
	"grameenkart/db"
	"grameenkart/handlers"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Error while loading .env file")
	}
}

func withMiddleware(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")

		// ✅ FIX: Proper response for preflight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		h(w, r)
	}
}

func main() {
	loadEnv()
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println("Error while printing host name:", err)
	} else {
		fmt.Println("Hostname:", hostname)
	}

	db.InitDB()
	http.HandleFunc("/signup", withMiddleware(handlers.SignupHandler))
	http.HandleFunc("/login", withMiddleware(handlers.LoginHandler))
	http.HandleFunc("/send-otp", withMiddleware(handlers.SendOTPHandler))
	http.HandleFunc("/verify-otp", withMiddleware(handlers.VerifyOTPHandler))
	http.HandleFunc("/reset-password", withMiddleware(handlers.ResetPasswordHandler))
	http.HandleFunc("/items", withMiddleware(handlers.GetItemsHandler))
	http.HandleFunc("/item-insert", withMiddleware(handlers.InsertItemHandler))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("Server is running 🚀"))
	})

	log.Println("Server running on http://localhost:8000")
	http.ListenAndServe(":8000", nil)
}
