package ident

import (
	"context"
	"net/url"
	"time"

	"github.com/halliday/go-openid"
)

const AudChangeEmail = "_change_email"

type InstructEmailChangeRequest struct {
	Email string `json:"email"`
}

func (server *Server) instructEmailChange(ctx context.Context, req *InstructEmailChangeRequest) error {
	sess := openid.CtxSession(ctx)
	if sess == nil {
		return e("unauthorized")
	}
	return server.InstructEmailChange(ctx, sess.Subject, req.Email)
}

func (server *Server) InstructEmailChange(ctx context.Context, sub string, email string) (err error) {
	user, err := server.UserStore.Userinfo(ctx, sub)
	if err != nil {
		return err
	}
	if user.Email == "" {
		return e("email_not_set")
	}
	go server.emailChangeEmail(user, email)
	return nil
}

type ChangeEmailRequest struct {
	ChangeEmailToken string `json:"changeEmailToken"`
}

func (server *Server) changeEmail(ctx context.Context, req *ChangeEmailRequest) (err error) {
	claims, err := server.ParseToken(req.ChangeEmailToken)
	if err != nil {
		return err
	}
	if aud, _ := claims[Audience].(string); aud != AudChangeEmail {
		return e("invalid_aud")
	}
	sub, _ := claims[Subject].(string)
	email, _ := claims["email"].(string)
	count, err := server.UserStore.UpdateUsers(ctx, Selection{Ids: []string{sub}}, &UserUpdate{Email: NewOption(email), EmailVerified: NewOption(true)})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrNoUser
	}
	return nil
}

func (server *Server) emailChangeEmail(user *openid.Userinfo, email string) {
	token, err := server.CreateToken(map[string]interface{}{
		Audience:  AudChangeEmail,
		Subject:   user.Subject,
		"email":   email,
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	})
	if err != nil {
		l.Err("err_prepare_token", "change-email", err)
		return
	}

	v := url.Values{
		"token": {token},
	}

	addr, auth, msg, err := server.prepareMail(server.ChangeEmailSubject, user.Email, server.ChangeEmailTemplate, &Email{
		Userinfo:    user,
		RedirectUri: joinUriParams(server.Config.AuthorizationEndpoint, v),
	})
	if err != nil {
		l.Err("err_prepare_email", "change-email", err)
		return
	}

	to := []string{email}
	start := time.Now()
	err = server.SendMail(addr, auth, server.EmailFrom, to, msg)
	duration := time.Since(start)
	if err != nil {
		l.Err("err_send_email", "change-email", err, "Email", email, "Username", user.PreferredUsername, "Locale", user.Locale, "Timing", duration)
		return
	}

	l.Info("email_sent", "change-email", "Email", email, "Username", user.PreferredUsername, "Locale", user.Locale, "Timing", duration)
}
