package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/hello/{name}", hello)

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	log.Println("Listening...")
	server.ListenAndServe() // Run the http server
}

func hello(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Hello %s!", name)))
}
