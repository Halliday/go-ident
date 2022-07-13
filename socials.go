package ident

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/halliday/go-openid"
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
		ExiresIn:     int64(time.Until(t.Expiry)),
	}, nil
}

func (p SocialProvider) Userinfo(ctx context.Context, server *Server, t *openid.TokenResponse) (info *openid.Userinfo, err error) {

	if t.IdToken != "" {
		claims := new(IdTokenClaims)
		parser := jwt.NewParser()
		// TODO: verify token from social provider
		_, _, err := parser.ParseUnverified(t.IdToken, claims)
		if err != nil {
			return nil, err
		}
		return &claims.Userinfo, nil
	}

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
		case "application/json":
			err = json.NewDecoder(resp.Body).Decode(userinfo)
			return userinfo, err
		default:
			return nil, e("social_userinfo_content_type", "ContentType", contentType)
		}
	}

	if t.Code != "" {
		t, err = p.Exchange(ctx, server, t.Code)
		if err != nil {
			return nil, err
		}
		return p.Userinfo(ctx, server, t)
	}

	return nil, e("social_token_type", "TokenType", t.TokenType)
}

type SocialLoginRequest struct {
	Iss string `json:"iss"`

	openid.TokenRequest
	ClientId     string `json:"clientId"`
	ResponseType string `json:"responseType"`
	Scope        string `json:"scope"`
	Nonce        string `json:"nonce"`
	State        string `json:"state"`
	RedirectUri  string `json:"redirectUri"`
}

type SocialLoginResponse struct {
	RedirectUri string `json:"redirectUri"`
}

func (server *Server) socialLogin(ctx context.Context, req *SocialLoginRequest) (resp *SocialLoginResponse, err error) {
	resp = new(SocialLoginResponse)

	p := server.socials[req.Iss]
	if p == nil {
		return nil, e("social_provider_not_found")
	}

	s := url.Values{
		"iss":           {req.Iss},
		"response_type": {req.ResponseType},
	}
	if req.RedirectUri != "" {
		s.Add("redirect_uri", req.RedirectUri)
	}
	if req.Scope != "" {
		s.Add("scope", req.Scope)
	}
	if req.Nonce != "" {
		s.Add("nonce", req.Nonce)
	}
	if req.State != "" {
		s.Add("state", req.State)
	}
	state := s.Encode()

	responseTypesSupported := p.Config.ResponseTypesSupported
	if responseTypesSupported == nil || stringSliceIncludes(responseTypesSupported, "code") {
		resp.RedirectUri = p.OAuth2Config(server).AuthCodeURL(state)
		return resp, nil
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
		if strings.Contains(p.Config.AuthorizationEndpoint, "?") {
			buf.WriteByte('&')
		} else {
			buf.WriteByte('?')
		}
		buf.WriteString(v.Encode())

		resp.RedirectUri = buf.String()
		return resp, nil
	}

	return nil, e("social_unsupported_response_types")
}

type CompleteSocialLoginRequest struct {
	Iss                  string `json:"iss"` // social provider
	openid.TokenResponse        // as obtained from social provider
	openid.TokenRequest
}

type CompleteSocialLoginResponse = openid.TokenResponse

func (server *Server) completeSocialLogin(ctx context.Context, req *CompleteSocialLoginRequest) (resp *CompleteSocialLoginResponse, err error) {

	p := server.socials[req.Iss]
	if p == nil {
		return nil, e("social_provider_not_found")
	}

	info, err := p.Userinfo(ctx, server, &req.TokenResponse)
	if err != nil {
		return nil, err
	}

	if info.Email == "" {
		info.EmailVerified = true
	}

	sub, err := server.UserStore.RegisterSocialUser(ctx, req.Iss, info)
	if err != nil {
		return nil, err
	}
	if sub == "" {
		return nil, openid.ErrNoUser
	}
	req.TokenRequest.Subject = sub

	return server.Authorize(ctx, &req.TokenRequest)

	// authResp, err := server.Authorize(ctx, &openid.AuthorizationRequest{
	// 	Subject:      sub,
	// 	Scope:        state.Get("scope"),
	// 	Nonce:        state.Get("nonce"),
	// 	ResponseType: state.Get("response_type"),
	// 	State:        state.Get("state"),
	// })
	// if err != nil {
	// 	tools.ServeError(resp, err)
	// 	return
	// }

	// var buf bytes.Buffer
	// buf.WriteString(server.Config.AuthorizationEndpoint)
	// if strings.Contains(server.Config.AuthorizationEndpoint, "?") {
	// 	buf.WriteByte('&')
	// } else {
	// 	buf.WriteByte('?')
	// }

	// buf.WriteString(authResp.EncodeValues().Encode())

	// http.Redirect(resp, req, buf.String(), http.StatusFound)
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
