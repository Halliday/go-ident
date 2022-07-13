package identutil

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/halliday/go-openid"
)

type memSession struct {
	createdAt   time.Time
	refreshedAt time.Time
	numRefresh  int
	audience    string
	subject     string
	scopes      []string
}

type memSessionStore struct {
	sessions map[uuid.UUID]*memSession
}

func NewMemSessionStore() openid.SessionStore {
	sessionStore := new(memSessionStore)
	sessionStore.sessions = make(map[uuid.UUID]*memSession)
	return sessionStore
}

func (store *memSessionStore) RefreshSession(ctx context.Context, aud string, id string) (sub string, scopes []string, err error) {
	sess := store.sessions[uuid.MustParse(id)]
	if sess == nil {
		return "", nil, nil
	}
	sess.refreshedAt = time.Now()
	sess.numRefresh++
	l.Info("session_refreshed", "Id", id, "NumRefresh", sess.numRefresh, "CreatedAt", sess.createdAt)
	return sess.subject, sess.scopes, nil
}

func (store *memSessionStore) CreateSession(ctx context.Context, aud string, sub string, scopes []string) (sess string, err error) {
	id := uuid.New()
	now := time.Now()
	store.sessions[id] = &memSession{
		createdAt:   now,
		refreshedAt: now,
		audience:    aud,
		subject:     sub,
		scopes:      scopes,
	}
	l.Info("session_created", "Id", id, "Aud", aud, "Sub", sub, "Scopes", strings.Join(scopes, " "))
	return id.String(), nil
}

func (store *memSessionStore) RevokeSession(ctx context.Context, aud string, sess string) (err error) {
	id, err := uuid.Parse(sess)
	if err != nil {
		return err
	}
	if sess, ok := store.sessions[id]; ok {
		delete(store.sessions, id)
		l.Info("session_revoked", "Id", id, "Aud", aud, "Sub", sess.subject, "Scopes", strings.Join(sess.scopes, " "))
	}
	return nil
}
