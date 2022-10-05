package ident

import (
	"context"

	"github.com/halliday/go-openid"
)

type SessionSelection struct {
	Id  string `json:"id"`  // session id
	Sub string `json:"sub"` // user id
}

type UpdateSessionRequest struct {
	SessionSelection

	AddScopes    []string `json:"addScopes"`
	RemoveScopes []string `json:"removeScopes"`
}

type UpdateSessionResponse struct {
	NumUpdated int `json:"numUpdated"`
}

func (s *Server) updateSessions(ctx context.Context, req *UpdateSessionRequest) (resp *UpdateSessionResponse, err error) {
	if !openid.CtxSession(ctx).HasScope(s.ScopeAdmin) {
		return nil, e("missing_scope", s.ScopeAdmin)
	}
	resp = new(UpdateSessionResponse)
	resp.NumUpdated, err = s.SessionStore.UpdateSessions(ctx, req.Id, req.Sub, req.AddScopes, req.RemoveScopes)
	return resp, err
}
