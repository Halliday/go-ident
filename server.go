package ident

import (
	"html/template"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	_ "embed"

	"github.com/halliday/go-openid"
	"github.com/halliday/go-router"
	"github.com/halliday/go-rpc"
	"golang.org/x/net/context"
)

const Audience = "aud"
const Subject = "sub"
const ExpiresAt = "exp"
const IssuedAt = "iat"

type Server struct {
	Addr string

	*openid.Server
	route   *router.Route
	socials map[string]*SocialProvider

	SessionStore SessionStore
	UserStore    UserStore

	EmailHost                 string
	EmailHostPort             int
	EmailFrom                 string
	EmailFromDisplayName      string
	EmailEnableTLS            bool
	EmailEnaleStartTLS        bool
	EmailEnableAuthentication bool
	EmailUsername             string
	EmailPassword             string

	CompleteRegistrationTemplate *template.Template
	CompleteRegistrationSubject  string

	ChangeEmailTemplate *template.Template
	ChangeEmailSubject  string

	PasswordResetTemplate    *template.Template
	PasswordResetSubject     string
	PasswordResetDelay       time.Duration
	PasswordResetTokenExpiry time.Duration

	SendMail func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

type UserUpdate struct {
	openid.Userinfo

	NewPassword string
	OldPassword string
}

type UserStore interface {
	openid.UserStore

	LoginUser(ctx context.Context, username string, password string, scopes Scopes) (info *openid.Userinfo, grantedScopes Scopes, err error)

	UpdateUser(ctx context.Context, info *UserUpdate) (err error)
	// UpdateUserPassword(ctx context.Context, sub string, password string) (err error)
	// UpdateUserEmailVerified(ctx context.Context, sub string) (err error)

	RegisterUser(ctx context.Context, info *openid.Userinfo, password *string) (sub string, err error)

	RegisterSocialUser(ctx context.Context, social string, info *openid.Userinfo) (sub string, err error)

	FindUserPasswordReset(ctx context.Context, email string) (*openid.Userinfo, error)

	DeleteUsers(ctx context.Context, subs []string) (numDeleted int, err error)
}

type Store interface {
	UserStore
	SessionStore
}

type SessionStore = openid.SessionStore

func NewServer(addr string, sessionStore SessionStore, userStore UserStore, socials []*SocialProvider, next http.Handler) *Server {

	sps := make(map[string]*SocialProvider)
	for _, p := range socials {
		sps[p.Config.Issuer] = p
	}

	server := &Server{
		Addr:         addr,
		socials:      sps,
		SessionStore: sessionStore,
		UserStore:    userStore,

		CompleteRegistrationTemplate: mustParseTemplate("email-complete-registration", templateEmailCompleteRegistration),
		CompleteRegistrationSubject:  "Complete your registration",

		ChangeEmailTemplate: mustParseTemplate("email-change-email", templateEmailChangeEmail),
		ChangeEmailSubject:  "Confirm your email address",

		PasswordResetTemplate:    mustParseTemplate("email-reset-password", templateEmailResetPassword),
		PasswordResetSubject:     "Reset your password",
		PasswordResetDelay:       time.Minute * 5,
		PasswordResetTokenExpiry: time.Hour,

		SendMail: smtp.SendMail,
	}

	server.route = &router.Route{
		Paths: map[string]http.Handler{
			"ident": &router.Route{
				Paths: map[string]http.Handler{
					"login": rpc.MustNew(server.login),

					"begin-registration":    rpc.MustNew(server.beginRegistration),
					"complete-registration": rpc.MustNew(server.completeRegistration),

					"begin-reset-password":    rpc.MustNew(server.beginResetPassword),
					"complete-reset-password": rpc.MustNew(server.completeResetPassword),

					"begin-change-email":    rpc.MustNew(server.beginChangeEmail),
					"complete-change-email": rpc.MustNew(server.completeChangeEmail),

					// "change-password": rpc.MustNew(server.changePassword),

					"delete-user": rpc.MustNew(server.deleteUser),

					"social-login":          rpc.MustNew(server.socialLogin),
					"complete-social-login": rpc.MustNew(server.completeSocialLogin),

					"social-providers": &router.Route{
						Methods: map[string]http.Handler{
							http.MethodGet: rpc.MustNew(server.getSocialProviders),
						},
						// Paths: map[string]http.Handler{
						// 	"login": rpc.MustNew(server.socialLogin),
						// },
					},

					"update-user": rpc.MustNew(server.updateUser),
				},
			},
		},
		Next: next,
	}

	server.Server = openid.NewServer(addr, sessionStore, userStore, nil, server.route)

	return server
}

func (server *Server) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	server.Server.ServeHTTP(resp, req)
}

//

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`

	ClientId     string `json:"clientId"`
	Scope        string `json:"scope"`
	Nonce        string `json:"nonce"`
	ResponseType string `json:"responseType"`
}

type LoginResponse = openid.TokenResponse

var ErrInvalidCredentials = e("invalid_credentials")
var ErrNoUser = openid.ErrNoUser

func (server *Server) login(ctx context.Context, req *LoginRequest) (resp *LoginResponse, err error) {
	scopes := NewScopes(req.Scope)
	user, grantedScopes, err := server.UserStore.LoginUser(ctx, req.Username, req.Password, scopes)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrInvalidCredentials
	}
	if user.Email != "" && !user.EmailVerified {
		return nil, e("email_unverified")
	}
	return server.Authorize(ctx, &openid.TokenRequest{
		Subject:      user.Subject,
		ClientId:     req.ClientId,
		ResponseType: req.ResponseType,
		Scope:        grantedScopes.String(),
		Nonce:        req.Nonce,
	})
}

//

// type AskResetPasswordRequest struct {
// 	Email       string
// 	RedirectUri string
// }

// func (server *Server) askResetPassword(ctx context.Context, req *AskResetPasswordRequest) (err error) {
// 	user, err := server.UserStore.FindUserPasswordReset(ctx, req.Email)
// 	if err != nil {
// 		return err
// 	}
// 	go server.emailResetPassword(user, req.RedirectUri)
// 	return nil
// }

//

type socialProvider struct {
	Issuer string `json:"iss"`
	// Picture string `json:"picture"`
}
type socialProvidersResponse []socialProvider

func (server *Server) getSocialProviders(ctx context.Context) (resp socialProvidersResponse, err error) {
	resp = make(socialProvidersResponse, len(server.socials))
	i := 0
	for _, p := range server.socials {
		resp[i] = socialProvider{
			Issuer: p.Config.Issuer,
			// Picture: server.Addr + "ident/social-providers/" + p.Name + "/picture.png",
		}
		i++
	}
	return resp, nil
}

////////////////////////////////////////////////////////////////////////////////

const AudChangeEmail = "_change_email"

func (server *Server) beginChangeEmail(ctx context.Context, email string) error {
	sess := openid.CtxSession(ctx)
	if sess == nil {
		return e("unauthorized")
	}
	return server.BeginChangeEmail(ctx, sess.Subject, email)
}

func (server *Server) BeginChangeEmail(ctx context.Context, sub string, email string) (err error) {
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

type CompleteChangeEmailRequest struct {
	Token string `json:"token"`
}

type CompleteChangeEmailResponse struct {
	Email string `json:"email"`
}

func (server *Server) completeChangeEmail(ctx context.Context, req *CompleteChangeEmailRequest) (resp *CompleteChangeEmailResponse, err error) {
	claims, err := server.ParseToken(req.Token)
	if err != nil {
		return nil, err
	}
	if aud, _ := claims[Audience].(string); aud != AudChangeEmail {
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
	resp = &CompleteChangeEmailResponse{
		Email: email,
	}
	return resp, nil
}

func (server *Server) emailChangeEmail(user *openid.Userinfo, email string) {
	token, err := server.CreateToken(map[string]interface{}{
		Audience: AudChangeEmail,
		Subject:  user.Subject,
		"email":  email,
	})
	if err != nil {
		l.Err("err_prepare_token", "change-email", err)
		return
	}

	var b strings.Builder
	b.WriteString(server.Config.AuthorizationEndpoint)
	if strings.Contains(server.Config.AuthorizationEndpoint, "?") {
		b.WriteByte('&')
	} else {
		b.WriteByte('?')
	}
	b.WriteString("change_email_token=")
	b.WriteString(token)

	redirectUri := b.String()

	addr, auth, msg, err := server.prepareMail(server.ChangeEmailSubject, user.Email, server.ChangeEmailTemplate, &Email{
		Userinfo:    user,
		RedirectUri: redirectUri,
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

////////////////////////////////////////////////////////////////////////////////

//go:embed templates/email-change-email.html
var templateEmailChangeEmail string

//go:embed templates/email-complete-registration.html
var templateEmailCompleteRegistration string

//go:embed templates/email-reset-password.html
var templateEmailResetPassword string

func mustParseTemplate(name string, data string) *template.Template {
	template, err := template.New(name).Parse(string(data))
	if err != nil {
		panic(err)
	}
	return template
}

////////////////////////////////////////////////////////////////////////////////

// type ChangePasswordRequest struct {
// 	OldPassword string `json:"oldPassword"`
// 	NewPassword string `json:"newPassword"`
// }

// func (server *Server) changePassword(ctx context.Context, req *ChangePasswordRequest) error {
// 	sess := openid.CtxSession(ctx)
// 	if sess == nil {
// 		return e("unauthorized")
// 	}
// 	if req.OldPassword == "" || req.NewPassword == "" {
// 		return e("bad_request")
// 	}
// 	info := &UserinfoUpdate{
// 		Userinfo: openid.Userinfo{
// 			Subject: sess.Subject,
// 		},
// 		OldPassword: req.OldPassword,
// 		NewPassword: req.NewPassword,
// 	}
// 	return server.UserStore.UpdateUser(ctx, info)
// }

func (server *Server) updateUser(ctx context.Context, info *UserUpdate) error {
	sess := openid.CtxSession(ctx)
	if sess == nil {
		return e("unauthorized")
	}
	if info.Subject != "" || info.CreatedAt != 0 || // read-only
		info.SocialProviders != nil || info.UpdatedAt != 0 || // read-only
		(info.OldPassword != "" && info.NewPassword == "") { // must be set together
		return e("bad_request")
	}

	if info.Email != "" {
		if err := server.BeginChangeEmail(ctx, sess.Subject, info.Email); err != nil {
			return err
		}
		info.Email = ""
	}

	info.Subject = sess.Subject
	info.PreferredUsernameVerified = false
	info.EmailVerified = false
	info.PhoneNumberVerified = false
	return server.UserStore.UpdateUser(ctx, info)
}

////////////////////////////////////////////////////////////////////////////////

func (server *Server) deleteUser(ctx context.Context) error {
	sess := openid.CtxSession(ctx)
	if sess == nil {
		return e("unauthorized")
	}
	_, err := server.UserStore.DeleteUsers(ctx, []string{sess.Subject})
	return err
}
