package ident

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/halliday/go-openid"
)

type BeginResetPasswordRequest struct {
	Email string

	ClientId     string
	ResponseType string
	Scope        string
	Nonce        string
	State        string
	RedirectUri  string
}

func (server *Server) beginResetPassword(ctx context.Context, req *BeginResetPasswordRequest) (err error) {
	user, err := server.UserStore.FindUserPasswordReset(ctx, req.Email)
	if err != nil {
		return err
	}
	if user == nil {
		return openid.ErrNoUser
	}
	if user.Subject == "" {
		return e("bad_store_sub")
	}
	go server.emailResetPassword(user, req)
	return nil
}

func (server *Server) emailResetPassword(user *openid.Userinfo, req *BeginResetPasswordRequest) {

	resetPasswordToken, err := server.CreateToken(map[string]interface{}{
		Subject:   user.Subject,
		Audience:  ResetPasswordAud,
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	})
	if err != nil {
		l.Err("prepare_reset_email", err, "Email", user.Email, "Username", user.PreferredUsername, "Locale", user.Locale)
		return
	}

	v := url.Values{
		"reset_password_token": {resetPasswordToken},
		"client_id":            {req.ClientId},
		"response_type":        {req.ResponseType},
		"email":                {user.Email},
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

	addr, auth, msg, err := server.prepareMail("Passwort Zurücksetzen", user.Email, server.PasswordResetTemplate, &Email{
		Userinfo:    user,
		RedirectUri: b.String(),
	})
	if err != nil {
		l.Err("prepare_reset_email", err, "Email", user.Email, "Username", user.PreferredUsername, "Locale", user.Locale)
		return
	}
	to := []string{user.Email}
	start := time.Now()
	err = server.SendMail(addr, auth, server.EmailFrom, to, msg)
	duration := time.Since(start)
	if err != nil {
		l.Err("reset_email_send", err, "Email", user.Email, "Username", user.PreferredUsername, "Locale", user.Locale, "Timing", duration)
	} else {
		l.Info("reset_email_sent", "Email", user.Email, "Username", user.PreferredUsername, "Locale", user.Locale, "Timing", duration)
	}
}

type ResetPasswordRequest struct {
	ResetPasswordToken string
	Password           string
}

func (server *Server) completeResetPassword(ctx context.Context, req *ResetPasswordRequest) (err error) {

	claims, err := server.ParseToken(req.ResetPasswordToken)
	if err != nil {
		return err
	}
	if aud, _ := claims[Audience].(string); aud != ResetPasswordAud {
		return e("invalid_aud")
	}
	sub, _ := claims[Subject].(string)
	info := &UserUpdate{
		Userinfo: openid.Userinfo{
			Subject: sub,
		},
		NewPassword: req.Password,
	}
	return server.UserStore.UpdateUser(ctx, info)
}

////////////////////////////////////////////////////////////////////////////////

const ResetPasswordAud = "_password_reset"

// func (server *Server) ParseResetPasswordToken(resetPasswordToken string) (sub string, err error) {
// 	token, err := jwt.Parse(resetPasswordToken, func(token *jwt.Token) (interface{}, error) {
// 		if token.Method != jwt.SigningMethodHS256 {
// 			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
// 		}
// 		return server.AccessTokenKey, nil
// 	})
// 	if err != nil {
// 		switch er := err.(type) {
// 		case *jwt.ValidationError:
// 			if er.Errors&jwt.ValidationErrorExpired != 0 {
// 				return "", e("invalid_exp")
// 			}
// 		}
// 		return "", err
// 	}
// 	claims := token.Claims.(jwt.MapClaims)
// 	aud := claims["aud"].(string)
// 	if aud != ResetPasswordAud {
// 		return "", e("invalid_aud")
// 	}

// 	iss := claims["iss"].(string)
// 	if iss != server.Addr {
// 		return "", e("invalid_iss")
// 	}

// 	sub, ok := claims["sub"].(string)
// 	if !ok || !strings.HasPrefix(sub, openid.AccessTokenSubjectPrefix) {
// 		return "", e("invalid_sub")
// 	}
// 	sub = sub[len(openid.AccessTokenSubjectPrefix):]
// 	return sub, nil
// }

// func (server *Server) CreateResetPasswordToken(sub string) (string, error) {
// 	resetPasswordToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
// 		"aud": ResetPasswordAud,
// 		"iss": server.Addr,
// 		"sub": openid.AccessTokenSubjectPrefix + sub,
// 		"iat": time.Now().Unix(),
// 		"exp": time.Now().Add(server.PasswordResetTokenExpiry).Unix(),
// 	})
// 	return resetPasswordToken.SignedString(server.AccessTokenKey)
// }

////////////////////////////////////////////////////////////////////////////////
