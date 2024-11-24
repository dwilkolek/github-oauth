package internal

import (
	"dwilkolek/github-oauth/internal/auth"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func NewService() Service {
	return Service{
		auth.NewService(),
	}
}

type Service struct {
	auth.AuthService
}

func (s *Service) EnvHandler(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("%s=%s", name, os.Getenv(name))))
}

func (s *Service) HelloHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session-jwt")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("no cookie"))
		return
	}

	userDetails, err := s.GetUserDetails(cookie.Value)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("%v", err)))
		return
	}

	jsonBody, err := json.Marshal(userDetails)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("%v", err)))
		return
	}

	w.Write(jsonBody)
	w.WriteHeader(http.StatusOK)
}

func (s *Service) LoginHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.GetLoginUrl(), http.StatusTemporaryRedirect)
}

func (s *Service) GithubCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	jwtToken, err := s.ExchangeGithubCodeForJwt(code)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(fmt.Sprintf("%v", err)))
		return
	}
	cookie := http.Cookie{Name: "session-jwt",
		Value:    jwtToken.Token,
		Expires:  jwtToken.ExpireAt,
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
		Path:     "/",
	}

	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
