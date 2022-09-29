package ident

import (
	"context"
	"net/url"
	"time"

	"github.com/halliday/go-openid"
)

const ResetPasswordAud = "_reset_password"

type InstructPasswordResetRequest struct {
	Email       string `json:"email"`
	RedirectUri string `json:"redirectUri"`
}

func (server *Server) instructPasswordReset(ctx context.Context, req *InstructPasswordResetRequest) (err error) {
	users, _, err := server.UserStore.FindUsers(ctx, Selection{Email: req.Email}, "", 1)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		return openid.ErrNoUser
	}
	user := users[0]
	if user.Subject == "" {
		return e("bad_store_sub")
	}
	go server.emailPasswordReset(&user.Userinfo, req)
	return nil
}

func (server *Server) emailPasswordReset(user *Userinfo, req *InstructPasswordResetRequest) {

	resetPasswordToken, err := server.CreateToken(map[string]interface{}{
		Audience:  ResetPasswordAud,
		Subject:   user.Subject,
		"email":   user.Email,
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	})
	if err != nil {
		l.Err("prepare_reset_email", err, "Email", user.Email, "Username", user.PreferredUsername, "Locale", user.Locale)
		return
	}

	v := url.Values{"token": {resetPasswordToken}}
	if req.RedirectUri != "" {
		v.Set("redirect_uri", req.RedirectUri)
	}

	addr, auth, msg, err := server.prepareMail(server.PasswordResetSubject, user.Email, server.PasswordResetTemplate, &Email{
		Userinfo:    user,
		RedirectUri: joinUriParams(server.Config.AuthorizationEndpoint, v),
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
	ResetPasswordToken string `json:"resetPasswordToken"`
	Password           string `json:"password"`
	RedirectUri        string `json:"redirectUri"`
}

func (server *Server) resetPassword(ctx context.Context, req *ResetPasswordRequest) (err error) {
	claims, err := server.ParseToken(req.ResetPasswordToken)
	if err != nil {
		return err
	}
	if aud, _ := claims[Audience].(string); aud != ResetPasswordAud {
		return e("invalid_aud")
	}
	sub, _ := claims[Subject].(string)
	count, err := server.UserStore.UpdateUsers(ctx, Selection{Ids: []string{sub}}, &UserUpdate{NewPassword: NewOption(req.Password)})
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNoUser
	}
	return
}

////////////////////////////////////////////////////////////////////////////////
