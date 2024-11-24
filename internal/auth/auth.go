package auth

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"os"
	"time"
)

type authDetails struct {
	AccessToken           string    `json:"access_token"`
	ExpiresIn             int       `json:"expires_in"`
	RefreshToken          string    `json:"refresh_token"`
	RefreshTokenExpiresIn int       `json:"refresh_token_expires_in"`
	TokenType             string    `json:"token_type"`
	Scope                 string    `json:"scope"`
	CreatedAt             time.Time `json:"created_at"`
}

func (a authDetails) isExpired() bool {
	return time.Now().After(a.CreatedAt.Add(time.Duration(a.ExpiresIn) * time.Second))
}

func (a authDetails) canRefresh() bool {
	return time.Now().Before(a.CreatedAt.Add(time.Duration(a.RefreshTokenExpiresIn) * time.Second))
}

type AuthService struct {
	users        map[string]authDetails
	jwtToken     []byte
	clientId     string
	clientSecret string
}

type JwtToken struct {
	Token    string
	ExpireAt time.Time
}

func NewService() AuthService {
	return AuthService{
		clientId:     os.Getenv("CLIENT_ID"),
		clientSecret: os.Getenv("CLIENT_SECRET"),
		jwtToken:     []byte(os.Getenv("JWT_TOKEN")),
		users:        make(map[string]authDetails),
	}
}

type accessTokenResponse struct {
	AccessToken           string `json:"access_token"`
	ExpiresIn             int    `json:"expires_in"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in"`
	TokenType             string `json:"token_type"`
	Scope                 string `json:"scope"`
}

func (s *AuthService) getActiveToken(jwtToken string) (string, error) {
	claims, err := s.getClaims(jwtToken)
	if err != nil {
		return "", fmt.Errorf("claims not valid: %v", err)
	}

	authToken, hasToken := s.users[claims.Subject]
	userId := claims.Subject
	if !hasToken {
		return "", fmt.Errorf("user %s not found", userId)
	}
	if authToken.isExpired() && !authToken.canRefresh() {
		return "", fmt.Errorf("user={%s} not authorized", userId)
	}
	if authToken.isExpired() {
		authToken, err := s.refreshAccessToken(authToken.RefreshToken)
		if err != nil {
			return "", fmt.Errorf("user={%s} couldn't refresh access token", userId)
		}
		s.users[userId] = authDetails{
			AccessToken:           authToken.AccessToken,
			ExpiresIn:             authToken.ExpiresIn,
			RefreshToken:          authToken.RefreshToken,
			RefreshTokenExpiresIn: authToken.RefreshTokenExpiresIn,
			TokenType:             authToken.TokenType,
			Scope:                 authToken.Scope,
			CreatedAt:             time.Now(),
		}
	}
	return s.users[userId].AccessToken, nil
}

func (s *AuthService) getClaims(jwtToken string) (jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(jwtToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return s.jwtToken, nil
	})
	if err != nil {
		return jwt.RegisteredClaims{}, err
	} else if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok {
		return *claims, nil
	} else {
		return jwt.RegisteredClaims{}, fmt.Errorf("failed to get claims")
	}
}
func (s *AuthService) GetUserDetails(jwtToken string) (UserDetails, error) {
	accessToken, err := s.getActiveToken(jwtToken)
	if err != nil {
		return UserDetails{}, err
	}
	return fetchUserDetails(accessToken)
}

func (s *AuthService) makeJwtToken(accessToken accessTokenResponse) (string, error) {
	user, err := fetchUserDetails(accessToken.AccessToken)
	if err != nil {
		return "", err
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: user.Login,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(
			time.Duration(accessToken.ExpiresIn) * time.Second)),
	})
	s.users[user.Login] = authDetails{
		AccessToken:           accessToken.AccessToken,
		ExpiresIn:             accessToken.ExpiresIn,
		RefreshToken:          accessToken.RefreshToken,
		RefreshTokenExpiresIn: accessToken.RefreshTokenExpiresIn,
		TokenType:             accessToken.TokenType,
		Scope:                 accessToken.Scope,
		CreatedAt:             time.Now(),
	}
	return jwtToken.SignedString(s.jwtToken)
}

func (s *AuthService) GetLoginUrl() string {
	return "https://github.com/login/oauth/authorize?scope=user:email&client_id=" + s.clientId
}
func (s *AuthService) ExchangeGithubCodeForJwt(code string) (JwtToken, error) {
	accessToken, err := s.submitAccessToken(code)
	if err != nil {
		return JwtToken{}, err
	}
	jwtToken, err := s.makeJwtToken(accessToken)
	if err != nil {
		return JwtToken{}, err
	}

	return JwtToken{
		token:    jwtToken,
		expireAt: time.Now().Add(time.Duration(accessToken.ExpiresIn) * time.Second),
	}, nil
}

func (s *AuthService) submitAccessToken(code string) (accessTokenResponse, error) {
	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, "https://github.com/login/oauth/access_token", nil)
	q := req.URL.Query()
	q.Add("client_id", s.clientId)
	q.Add("client_secret", os.Getenv("CLIENT_SECRET"))
	q.Add("code", code)
	req.URL.RawQuery = q.Encode()
	req.Header.Add("Accept", "application/json")

	res, _ := client.Do(req)
	defer res.Body.Close()
	var target accessTokenResponse
	err := json.NewDecoder(res.Body).Decode(&target)
	if err != nil {
		return accessTokenResponse{}, err
	}

	return target, nil
}

func (s *AuthService) refreshAccessToken(refreshToken string) (accessTokenResponse, error) {
	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, "https://github.com/login/oauth/access_token", nil)
	q := req.URL.Query()
	q.Add("client_id", s.clientId)
	q.Add("client_secret", os.Getenv("CLIENT_SECRET"))
	q.Add("refresh_token", refreshToken)
	q.Add("grant_type", "refresh_token")
	req.URL.RawQuery = q.Encode()
	req.Header.Add("Accept", "application/json")

	res, _ := client.Do(req)
	defer res.Body.Close()
	var target accessTokenResponse
	err := json.NewDecoder(res.Body).Decode(&target)

	if err != nil {
		return accessTokenResponse{}, err
	}
	return target, nil
}

type UserDetails struct {
	Login      string      `json:"login"`
	Id         int         `json:"id"`
	AvatarUrl  string      `json:"avatar_url"`
	GravatarId string      `json:"gravatar_id"`
	Name       string      `json:"name"`
	Company    interface{} `json:"company"`
	Email      interface{} `json:"email"`
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
}

func fetchUserDetails(accessToken string) (UserDetails, error) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return UserDetails{}, err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)

	res, _ := client.Do(req)
	defer res.Body.Close()

	var target UserDetails
	err = json.NewDecoder(res.Body).Decode(&target)
	if err != nil {
		return UserDetails{}, err
	}

	return target, nil
}
