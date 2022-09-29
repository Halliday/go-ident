package ident

import (
	"html/template"
	"net/http"
	"net/smtp"
	"time"

	_ "embed"

	"github.com/halliday/go-openid"
	"github.com/halliday/go-router"
	"github.com/halliday/go-rpc"
	"golang.org/x/net/context"
)

const Issuer = "iss"
const Audience = "aud"
const Subject = "sub"
const ExpiresAt = "exp"
const IssuedAt = "iat"

type Server struct {
	*openid.Server

	route   *router.Route
	Api     map[string]http.Handler
	socials map[string]*SocialProvider

	ScopeAdmin string

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
	Name       Option[string] `json:"name,omitempty"`
	GivenName  Option[string] `json:"given_name,omitempty"`
	FamilyName Option[string] `json:"family_name,omitempty"`
	MiddleName Option[string] `json:"middle_name,omitempty"`
	Nickname   Option[string] `json:"nickname,omitempty"`

	PreferredUsername Option[string] `json:"preferred_username,omitempty"`
	// requires priviliged scope
	PreferredUsernameVerified Option[bool] `json:"preferred_username_verified,omitempty"`

	Email Option[string] `json:"email,omitempty"`
	// requires priviliged scope
	EmailVerified Option[bool] `json:"email_verified,omitempty"`

	Gender      Option[string] `json:"gender,omitempty"`
	Birthdate   Option[string] `json:"birthdat,omitempty"`
	Zoneinfo    Option[string] `json:"zoneinfo,omitempty"`
	Locale      Option[string] `json:"locale,omitempty"`
	PhoneNumber Option[string] `json:"phone_number,omitempty"`
	// requires priviliged scope
	PhoneNumberVerified Option[bool]    `json:"phone_number_verified,omitempty"`
	Address             *openid.Address `json:"address,omitempty"`

	// requires priviliged scope
	Suspended Option[bool] `json:"suspended,omitempty"`

	NewPassword Option[string] `json:"new_password,omitempty"`
	// omitting this field requires priviliged scope
	OldPassword Option[string] `json:"old_password,omitempty"`
}

func (u UserUpdate) MarshalJSON() ([]byte, error) {
	return MarshalJSONOptionStruct(u)
}

type Selection struct {
	All    bool     `json:"all,omitempty"`
	Ids    []string `json:"ids,omitempty"`
	Email  string   `json:"email,omitempty"`
	Search string   `json:"search,omitempty"`
}

func (sel Selection) Empty() bool {
	return !sel.All && len(sel.Ids) == 0 && sel.Email == "" && sel.Search == ""
}

type Userinfo = openid.Userinfo

type User struct {
	Userinfo

	Suspended bool `json:"suspended,omitempty"`
	// Rank float32 `json:"rank,omitempty"` // when searching for users

	// only set when creating a new user
	Password Option[string] `json:"password,omitempty"`

	// SocialProviders map[string]string `json:"social_providers,omitempty"`
}

type UserStore interface {
	openid.UserStore

	LoginUser(ctx context.Context, username string, password string) (sub string, err error)

	RegisterUsers(ctx context.Context, iss string, ignoreEmails bool, users []*User) (ids []string, err error)

	UpdateUsers(ctx context.Context, sel Selection, u *UserUpdate) (numUpdated int, err error)

	DeleteUsers(ctx context.Context, sel Selection) (numDeleted int, err error)

	FindUsers(ctx context.Context, sel Selection, pageToken string, pageSize int) (users []*User, nextPageToken string, err error)

	CountUsers(ctx context.Context, sel Selection) (numSel int, numTotal int, err error)
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
		socials:    sps,
		ScopeAdmin: "admin",

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

	server.Api = map[string]http.Handler{
		"login":  rpc.MustNew(server.login),
		"logout": rpc.MustNew(server.logout),

		"register":              rpc.MustNew(server.register),
		"complete-registration": rpc.MustNew(server.completeRegistration),

		"instruct-password-reset": rpc.MustNew(server.instructPasswordReset),
		"reset-password":          rpc.MustNew(server.resetPassword),

		"instruct-email-change": rpc.MustNew(server.instructEmailChange),
		"change-email":          rpc.MustNew(server.changeEmail),

		"social-login": &router.Route{
			Methods: map[string]http.Handler{
				http.MethodGet:  rpc.MustNew(server.socialLogin),
				http.MethodPost: rpc.MustNew(server.postSocialLogin),
			},
		},
		"exchange-social-login": rpc.MustNew(server.exchangeSocialLogin),

		"social-providers": &router.Route{
			Methods: map[string]http.Handler{
				http.MethodGet: rpc.MustNew(server.getSocialProviders),
			},
		},

		"users": &router.Route{
			Methods: map[string]http.Handler{
				http.MethodGet:    rpc.MustNew(server.getUsers),
				http.MethodPost:   rpc.MustNew(server.insertUsers),
				http.MethodDelete: rpc.MustNew(server.deleteUsers),
				http.MethodPatch:  rpc.MustNew(server.updateUsers),
			},
			Paths: map[string]http.Handler{
				"self": &router.Route{
					Methods: map[string]http.Handler{
						http.MethodPatch:  rpc.MustNew(server.updateSelf),
						http.MethodDelete: rpc.MustNew(server.deleteSelf),
					},
				},
			},
		},
	}

	server.route = &router.Route{
		Paths: map[string]http.Handler{
			"ident": &router.Route{
				Paths: server.Api,
			},
		},
		Next: next,
	}

	server.Server = openid.NewServer(addr, sessionStore, userStore, server.route)

	return server
}

func (server *Server) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	server.Server.ServeHTTP(resp, req)
}

//

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`

	Nonce string `json:"nonce,omitempty"`
	Scope string `json:"scope,omitempty"`
}

type LoginResponse = openid.TokenResponse

var ErrInvalidCredentials = e("invalid_credentials")
var ErrNoUser = openid.ErrNoUser

func (server *Server) Login(ctx context.Context, aud string, scopes []string, username string, password string, nonce string) (refreshToken string, accessToken string, grantedScopes []string, expiresIn int64, idToken string, err error) {
	sub, err := server.UserStore.LoginUser(ctx, username, password)
	if err != nil {
		return "", "", nil, 0, "", err
	}
	if sub == "" {
		return "", "", nil, 0, "", ErrInvalidCredentials
	}
	return server.CreateSession(ctx, aud, sub, scopes, nonce)
}

func (server *Server) login(ctx context.Context, req *LoginRequest) (resp *LoginResponse, err error) {
	refreshToken, accessToken, scopes, expiresIn, idToken, err := server.Login(ctx, IdentAudience, NewScopes(req.Scope), req.Username, req.Password, req.Nonce)
	if err != nil {
		return nil, err
	}
	return &LoginResponse{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
		IdToken:      idToken,
		ExpiresIn:    expiresIn,
		Scope:        Scopes(scopes).String(),
	}, nil
}

type LogoutRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func (server *Server) logout(ctx context.Context, req *LogoutRequest) (err error) {
	aud, sess, err := server.ParseRefreshToken(req.RefreshToken)
	if err != nil {
		return err
	}
	return server.SessionStore.RevokeSession(ctx, aud, sess)
}

//

////////////////////////////////////////////////////////////////////////////////

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

type UpdateUsersRequest struct {
	Selection  Selection  `json:"sel"`
	UserUpdate UserUpdate `json:"update"`
}

type UpdateUserResponse struct {
	NumUpdated int `json:"numUpdated"`
}

func (server *Server) updateUsers(ctx context.Context, u *UpdateUsersRequest) (resp *UpdateUserResponse, err error) {
	if !openid.CtxSession(ctx).HasScope(server.ScopeAdmin) {
		return nil, e("missing_scope", server.ScopeAdmin)
	}
	resp = new(UpdateUserResponse)
	resp.NumUpdated, err = server.UserStore.UpdateUsers(ctx, u.Selection, &u.UserUpdate)
	return resp, err
}

func (server *Server) updateSelf(ctx context.Context, u *UserUpdate) error {
	sess := openid.CtxSession(ctx)
	if sess == nil {
		return e("unauthorized")
	}

	if u.EmailVerified.Valid || u.PreferredUsernameVerified.Valid || u.PhoneNumberVerified.Valid {
		// those fields are not updatable by the user
		return e("bad_request")
	}

	if u.NewPassword.Valid && !u.OldPassword.Valid {
		// this fields can only be used together
		return e("bad_request")
	}

	if u.Email.Valid {
		// users need to use the instruct-change-email endpoint to change their email
		u.EmailVerified = NewOption(false)
	}

	if u.PreferredUsername.Valid {
		u.PreferredUsernameVerified = NewOption(false)
	}

	if u.PhoneNumber.Valid {
		u.PhoneNumberVerified = NewOption(false)
	}

	count, err := server.UserStore.UpdateUsers(ctx, Selection{Ids: []string{sess.Subject}}, u)
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrNoUser
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////

type DeleteUsersRequest = Selection

type DeleteUserResponse struct {
	NumDeleted int `json:"numDeleted"`
}

func (server *Server) deleteUsers(ctx context.Context, req *DeleteUsersRequest) (resp *DeleteUserResponse, err error) {
	if !openid.CtxSession(ctx).HasScope(server.ScopeAdmin) {
		return nil, e("missing_scope", server.ScopeAdmin)
	}
	resp = new(DeleteUserResponse)
	resp.NumDeleted, err = server.UserStore.DeleteUsers(ctx, *req)
	return resp, err
}

func (server *Server) deleteSelf(ctx context.Context) error {
	sess := openid.CtxSession(ctx)
	if sess == nil {
		return e("unauthorized")
	}
	count, err := server.UserStore.DeleteUsers(ctx, Selection{Ids: []string{sess.Subject}})
	if err != nil {
		return err
	}
	if count != 1 {
		// the user might be deleted already, so we don't return an error
		return nil
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////

type GetUsersRequest struct {
	Selection
	PageToken string `json:"pageToken"`
	PageSize  int    `json:"pageSize"`
}

type GetUsersResponse struct {
	Users         []*User `json:"users"`
	NumFound      int     `json:"numFound"`
	NumTotal      int     `json:"numTotal"`
	NextPageToken string  `json:"nextPageToken,omitempty"`
}

func (server *Server) getUsers(ctx context.Context, req *GetUsersRequest) (resp *GetUsersResponse, err error) {
	if !openid.CtxSession(ctx).HasScope(server.ScopeAdmin) {
		return nil, e("missing_scope", server.ScopeAdmin)
	}
	users, nextPageToken, err := server.UserStore.FindUsers(ctx, req.Selection, req.PageToken, req.PageSize)
	if err != nil {
		return nil, err
	}
	resp = new(GetUsersResponse)
	resp.Users = users
	resp.NextPageToken = nextPageToken
	if req.PageSize > 0 && len(users) < req.PageSize && req.PageToken == "" {
		resp.NumFound = len(users)
		resp.NumTotal = len(users)
	} else {
		resp.NumFound, resp.NumTotal, err = server.UserStore.CountUsers(ctx, req.Selection)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

////////////////////////////////////////////////////////////////////////////////

type InsertUsersRequest struct {
	Users        []*User `json:"users"`
	Issuer       string  `json:"iss"`
	IgnoreEmails bool    `json:"ignoreEmails"`
}

type InsertUsersResponse struct {
	Ids []string `json:"ids"`
}

func (server *Server) insertUsers(ctx context.Context, req *InsertUsersRequest) (resp *InsertUsersResponse, err error) {
	if !openid.CtxSession(ctx).HasScope(server.ScopeAdmin) {
		return nil, e("missing_scope", server.ScopeAdmin)
	}
	resp = new(InsertUsersResponse)
	resp.Ids, err = server.UserStore.RegisterUsers(ctx, req.Issuer, req.IgnoreEmails, req.Users)
	if err != nil {
		return nil, err
	}
	return resp, err

}
