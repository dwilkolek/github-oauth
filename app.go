package main

import (
	"dwilkolek/github-oauth/internal"
	"embed"
	"github.com/joho/godotenv"
	"io/fs"
	"log"
	"net/http"
)

//go:embed public
var publicFiles embed.FS

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	service := internal.NewService()
	var publicFS = fs.FS(publicFiles)
	publicContent, _ := fs.Sub(publicFS, "public")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", service.LoginHandler)
	mux.HandleFunc("GET /api/hello", service.HelloHandler)
	//mux.HandleFunc("GET /api/env/{name}", service.EnvHandler)
	mux.HandleFunc("GET /api/oauth/callback", service.GithubCallbackHandler)
	mux.Handle("GET /", http.FileServer(http.FS(publicContent)))

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	log.Println("Starting server at port 8080...")
	err = server.ListenAndServe()
	if err != nil {
		log.Printf("Error starting server: %v", err)
	} // Run the http server
}
