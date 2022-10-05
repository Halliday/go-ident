package ident

import (
	"context"
	"net/url"
	"time"
)

//

type RegistrationRequest struct {
	Userinfo
	Password    string `json:"password"`
	RedirectUri string `json:"redirectUri"`
}

func (server *Server) register(ctx context.Context, req *RegistrationRequest) (err error) {

	req.Subject = ""
	req.EmailVerified = false
	req.PhoneNumberVerified = false
	if req.Email == "" {
		return e("bad_request")
	}

	ids, err := server.UserStore.RegisterUsers(ctx, "", false, []*NewUser{{Userinfo: req.Userinfo, Password: NewOption(req.Password)}})
	if err != nil {
		return err
	}
	if len(ids) != 1 {
		return e("bad_store_sub")
	}
	req.Subject = ids[0]

	go server.emailRegistration(req)
	return nil
}

//

type CompleteRegistrationRequest struct {
	RegistrationToken string `json:"registrationToken"`
	RedirectUri       string `json:"redirectUri"`
}

const RegistrationAud = "_complete_registration"

func (server *Server) completeRegistration(ctx context.Context, req *CompleteRegistrationRequest) (err error) {
	claims, err := server.ParseToken(req.RegistrationToken)
	if err != nil {
		return err
	}
	if aud, _ := claims[Audience].(string); aud != RegistrationAud {
		return e("invalid_aud")
	}
	sub, _ := claims[Subject].(string)
	email, _ := claims["email"].(string)

	return server.CompleteRegistration(ctx, sub, email)
}

func (server *Server) CompleteRegistration(ctx context.Context, sub string, email string) (err error) {
	count, err := server.UserStore.UpdateUsers(ctx, Selection{Ids: []string{sub}}, &UserUpdate{Email: NewOption(email), EmailVerified: NewOption(true)})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrNoUser
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////

func (server *Server) emailRegistration(req *RegistrationRequest) {
	user := &req.Userinfo

	token, err := server.CreateToken(map[string]interface{}{
		Audience: RegistrationAud,
		Subject:  user.Subject,
		"email":  user.Email,
	})
	if err != nil {
		l.Err("prepare_register_email", err, "Email", user.Email, "Username", user.PreferredUsername, "Locale", user.Locale)
		return
	}

	v := url.Values{"token": {token}}
	if req.RedirectUri != "" {
		v.Set("redirect_uri", req.RedirectUri)
	}

	addr, auth, msg, err := server.prepareMail(server.CompleteRegistrationSubject, user.Email, server.CompleteRegistrationTemplate, &Email{
		Userinfo:    user,
		RedirectUri: joinUriParams(server.Config.AuthorizationEndpoint, v),
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

func joinUriParams(uri string, v url.Values) string {
	return uri + "#" + v.Encode()

	// var b strings.Builder
	// b.WriteString(uri)
	// if strings.Contains(uri, "?") {
	// 	b.WriteByte('&')
	// } else {
	// 	b.WriteByte('?')
	// }
	// b.WriteString(v.Encode())
	// return b.String()
}
