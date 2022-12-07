package ident

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/halliday/go-openid"
	"github.com/halliday/go-rpc"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

type SocialProvider struct {
	Scope        string
	ClientId     string
	ClientSecret string
	Config       *openid.Configuration
}

func (p SocialProvider) OAuth2Config(server *Server) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.ClientId,
		ClientSecret: p.ClientSecret,
		Scopes:       splitScope(p.Scope),
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.Config.AuthorizationEndpoint,
			TokenURL: p.Config.TokenEndpoint,
		},
		RedirectURL: server.Config.AuthorizationEndpoint,
	}
}

func (p SocialProvider) Exchange(ctx context.Context, server *Server, code string) (*openid.TokenResponse, error) {
	t, err := p.OAuth2Config(server).Exchange(ctx, code)
	if err != nil {
		return nil, e("social_code_exchange_failed", err)
	}
	return &openid.TokenResponse{
		TokenType:    t.Type(),
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		ExpiresIn:    int64(time.Until(t.Expiry)),
	}, nil
}

func (p SocialProvider) Token(ctx context.Context, server *Server, a *openid.AuthResponse) (t *openid.TokenResponse, err error) {
	if a.Code != "" {
		t, err = p.Exchange(ctx, server, a.Code)
		if err != nil {
			return nil, err
		}
		return t, nil
	}
	if a.AccessToken != "" || a.RefreshToken != "" || a.IdToken != "" {
		return &openid.TokenResponse{
			TokenType:    a.TokenType,
			AccessToken:  a.AccessToken,
			RefreshToken: a.RefreshToken,
			IdToken:      a.IdToken,
			ExpiresIn:    a.ExpiresIn,
		}, nil
	}
	return t, e("bad_token")
}

func (p SocialProvider) Userinfo(ctx context.Context, server *Server, t *openid.TokenResponse) (info *openid.Userinfo, err error) {

	// if t.IdToken != "" {
	// 	claims := new(IdTokenClaims)
	// 	parser := jwt.NewParser()
	// 	// TODO: verify token from social provider
	// 	_, _, err := parser.ParseUnverified(t.IdToken, claims)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	return &claims.Userinfo, nil
	// }

	if t.AccessToken != "" && (t.TokenType == "" || strings.EqualFold(t.TokenType, "Bearer")) {
		req, err := http.NewRequest("GET", p.Config.UserinfoEndpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+t.AccessToken)
		req.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		userinfo := new(openid.Userinfo)
		contentType := resp.Header.Get("Content-Type")
		switch contentType {
		case "application/json", "application/json; charset=utf-8":
			err = json.NewDecoder(resp.Body).Decode(userinfo)
			return userinfo, err
		default:
			data, _ := io.ReadAll(resp.Body)
			log.Print("userinfo response: ", string(data))
			return nil, e("social_bad_userinfo_content_type", "ContentType", contentType)
		}
	}

	// if t.Code != "" {
	// 	t, err = p.Exchange(ctx, server, t.Code)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	return p.Userinfo(ctx, server, t)
	// }

	return nil, e("social_token_type", "TokenType", t.TokenType)
}

type SocialLoginRequest struct {
	Iss         string `json:"iss"`
	RedirectUri string `json:"redirectUri"`
}

type SocialLoginResponse struct {
	RedirectUri string `json:"redirectUri"`
}

func (server *Server) SocialLogin(iss string, redirectUri string) (redirectUri2 string, err error) {

	p := server.socials[iss]
	if p == nil {
		return "", e("social_provider_not_found")
	}

	s := url.Values{"iss": {iss}}
	if redirectUri != "" {
		s.Set("redirect_uri", redirectUri)
	}

	state := s.Encode()

	responseTypesSupported := p.Config.ResponseTypesSupported
	if responseTypesSupported == nil || stringSliceIncludes(responseTypesSupported, "code") {

		return p.OAuth2Config(server).AuthCodeURL(state), nil
	}

	if stringSliceIncludes(responseTypesSupported, "token id_token") || stringSliceIncludes(responseTypesSupported, "id_token") {
		responseType := "token id_token"
		if stringSliceIncludes(responseTypesSupported, "id_token") {
			responseType = "id_token"
		}
		var buf strings.Builder

		nonce := uuid.New().String()

		buf.WriteString(p.Config.AuthorizationEndpoint)
		v := url.Values{
			"response_type": {responseType},
			"client_id":     {p.ClientId},
			"scope":         {p.Scope},
			"state":         {state},
			"redirect_uri":  {server.Config.AuthorizationEndpoint},
			"nonce":         {nonce},
		}

		return joinUriParams(p.Config.AuthorizationEndpoint, v), nil
	}

	return "", e("social_unsupported_response_types")
}

func (server *Server) socialLogin(ctx context.Context, req *SocialLoginRequest) (err error) {
	redirectUri, err := server.SocialLogin(req.Iss, req.RedirectUri)
	if err != nil {
		return err
	}
	httpContext := rpc.FindContext(ctx).(*rpc.HTTPContext)
	http.Redirect(httpContext.Response, httpContext.Request, redirectUri, http.StatusSeeOther)
	return nil
}

func (server *Server) postSocialLogin(ctx context.Context, req *SocialLoginRequest) (resp *SocialLoginResponse, err error) {
	resp = new(SocialLoginResponse)
	resp.RedirectUri, err = server.SocialLogin(req.Iss, req.RedirectUri)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

type ExchangeSocialLoginRequest struct {
	Auth        openid.AuthResponse `json:"auth"`
	Scope       string              `json:"scope"`
	Nonce       string              `json:"nonce"`
	RedirectUri string              `json:"redirectUri"`
}

type ExchangeSocialLoginResponse = openid.TokenResponse

func (server *Server) exchangeSocialLogin(ctx context.Context, req *ExchangeSocialLoginRequest) (resp *ExchangeSocialLoginResponse, err error) {

	state, err := url.ParseQuery(req.Auth.State)
	if err != nil {
		return nil, e("bad_request", err)
	}
	// redirectUri := state.Get("redirect_uri")
	iss := state.Get("iss")

	p := server.socials[iss]
	if p == nil {
		return nil, e("social_provider_not_found")
	}

	token, err := p.Token(ctx, server, &req.Auth)
	if err != nil {
		return nil, err
	}

	info, err := p.Userinfo(ctx, server, token)
	if err != nil {
		return nil, err
	}

	scopes := NewScopes(req.Scope)

	// if info.Email == "" {
	// 	info.EmailVerified = true
	// }

	subs, err := server.UserStore.RegisterUsers(ctx, iss, false, []*NewUser{{Userinfo: *info}})
	if err != nil {
		return nil, err
	}
	if len(subs) != 1 {
		return nil, ErrNoUser
	}
	sub := subs[0]

	refreshToken, accessToken, scopes, expiresIn, idToken, err := server.CreateSession(ctx, IdentAudience, sub, scopes, req.Nonce)
	if err != nil {
		return nil, err
	}
	return &ExchangeSocialLoginResponse{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
		IdToken:      idToken,
		ExpiresIn:    expiresIn,
		Scope:        Scopes(scopes).String(),
	}, nil
}

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

type IdTokenClaims struct {
	openid.Userinfo
	Nonce string
}

func (claims IdTokenClaims) Valid() error {
	return nil
}
func splitScope(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Split(scope, " ")
}
