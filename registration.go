package ident

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/halliday/go-openid"
)

//

type BeginRegistrationRequest struct {
	openid.Userinfo
	Password string

	ClientId     string
	ResponseType string
	Scope        string
	Nonce        string
	State        string
	RedirectUri  string
}

func (server *Server) beginRegistration(ctx context.Context, req *BeginRegistrationRequest) (err error) {

	req.Subject = ""
	req.EmailVerified = false
	req.PhoneNumberVerified = false
	if req.Email == "" {
		return e("bad_request")
	}

	sub, err := server.UserStore.RegisterUser(ctx, &req.Userinfo, &req.Password)
	if err != nil {
		return err
	}
	if sub == "" {
		return e("bad_store_sub")
	}
	req.Subject = sub
	go server.emailRegistration(req)
	return nil
}

//

type CompleteRegistrationRequest struct {
	Token string

	Scope        string `json:"scope"`
	Nonce        string `json:"nonce"`
	ResponseType string `json:"responseType"`
}

type CompleteRegistrationResponse = openid.TokenResponse

func (server *Server) completeRegistration(ctx context.Context, req *CompleteRegistrationRequest) (resp *CompleteRegistrationResponse, err error) {
	claims, err := server.ParseToken(req.Token)
	if err != nil {
		return nil, err
	}
	if aud, _ := claims[Audience].(string); aud != RegistrationAud {
		return nil, e("invalid_aud")
	}
	sub, _ := claims[Subject].(string)
	email, _ := claims["email"].(string)
	info := &UserUpdate{
		Userinfo: openid.Userinfo{
			Subject:       sub,
			Email:         email,
			EmailVerified: true,
		},
	}
	err = server.UserStore.UpdateUser(ctx, info)
	if err != nil {
		return nil, err
	}

	return server.Authorize(ctx, &openid.TokenRequest{
		Subject:      sub,
		Scope:        req.Scope,
		Nonce:        req.Nonce,
		ResponseType: req.ResponseType,
	})
}

////////////////////////////////////////////////////////////////////////////////

const RegistrationAud = "_complete_registration"

// func (server *Server) ParseRegistrationToken(registrationToken string) (sub string, err error) {
// 	_, sub, err = server.ParseCustomToken(RegistrationAud, registrationToken)
// 	if err != nil {
// 		return "", err
// 	}
// 	return sub, nil
// }

// func (server *Server) CreateRegistrationToken(sub string) (string, error) {
// 	return server.CreateCustomToken(RegistrationAud, sub)
// }

func (server *Server) CreateToken(claims map[string]interface{}) (string, error) {
	if aud, _ := claims[Audience].(string); aud == "" {
		panic("CreateToken: missing aud")
	}
	if sub, _ := claims[Subject].(string); sub == "" {
		panic("CreateToken: missing sub")
	}
	mapClaims := jwt.MapClaims{
		"iss": server.Addr,
		"iat": time.Now().Unix(),
	}
	for key, value := range claims {
		mapClaims[key] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, mapClaims)
	return token.SignedString(server.AccessTokenKey)
}

func (server *Server) ParseToken(str string) (claims map[string]interface{}, err error) {
	token, err := jwt.Parse(str, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return server.AccessTokenKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims = token.Claims.(jwt.MapClaims)
	iss, _ := claims["iss"].(string)
	// aud, _ = claims["aud"].(string)
	// sub, _ = claims["sub"].(string)

	if iss != server.Addr {
		return claims, e("invalid_iss")
	}
	// if expectedAud != "" && aud != expectedAud {
	// 	return aud, sub, e("invalid_aud")
	// }
	return claims, nil
}

////////////////////////////////////////////////////////////////////////////////

func (server *Server) emailRegistration(req *BeginRegistrationRequest) {
	user := &req.Userinfo

	token, err := server.CreateToken(map[string]interface{}{
		Audience: RegistrationAud,
		Subject:  req.Subject,
		"email":  user.Email,
	})
	if err != nil {
		l.Err("prepare_register_email", err, "Email", user.Email, "Username", user.PreferredUsername, "Locale", user.Locale)
		return
	}

	v := url.Values{
		"registration_token": {token},
		"client_id":          {req.ClientId},
		"response_type":      {req.ResponseType},
	}
	if req.Scope != "" {
		v.Set("scope", req.Scope)
	}
	if req.State != "" {
		v.Set("state", req.State)
	}
	if req.Nonce != "" {
		v.Set("nonce", req.Nonce)
	}

	var b strings.Builder
	b.WriteString(server.Config.AuthorizationEndpoint)
	if strings.Contains(server.Config.AuthorizationEndpoint, "?") {
		b.WriteByte('&')
	} else {
		b.WriteByte('?')
	}
	b.WriteString(v.Encode())

	addr, auth, msg, err := server.prepareMail(server.CompleteRegistrationSubject, user.Email, server.CompleteRegistrationTemplate, &Email{
		Userinfo:    user,
		RedirectUri: b.String(),
	})
	if err != nil {
		l.Err("prepare_register_email", err, "Email", user.Email, "Username", user.PreferredUsername, "Locale", user.Locale)
		return
	}
	to := []string{user.Email}
	start := time.Now()
	err = server.SendMail(addr, auth, server.EmailFrom, to, msg)
	duration := time.Since(start)
	if err != nil {
		l.Err("register_email_send", err, "Email", user.Email, "Username", user.PreferredUsername, "Locale", user.Locale, "Timing", duration)
	} else {
		l.Info("register_email_sent", "Email", user.Email, "Username", user.PreferredUsername, "Locale", user.Locale, "Timing", duration)
	}
}
