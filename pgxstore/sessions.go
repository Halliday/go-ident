package pgxstore

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/halliday/go-ident"
	"github.com/jackc/pgx/v4"
)

func (store *Store) GetSession(ctx context.Context, aud string, sess string) (sub string, scopes []string, err error) {
	id, err := uuid.Parse(sess)
	if err != nil {
		return "", nil, ident.ErrInvalidCredentials
	}
	err = store.Pool.QueryRow(ctx, `
		SELECT sub, scopes
		FROM "`+store.SessionsTableName+`"
		WHERE id = $1
	`, id).Scan(&sub, &scopes)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil, ident.ErrInvalidCredentials
		}
		return "", nil, err
	}
	return sub, scopes, err
}

func (store *Store) RefreshSession(ctx context.Context, aud string, sess string, newScopes []string) (sub string, scopes []string, err error) {
	id, err := uuid.Parse(sess)
	if err != nil {
		return "", nil, ident.ErrInvalidCredentials
	}
	err = store.Pool.QueryRow(ctx, `UPDATE "`+store.SessionsTableName+`"
		SET
			refreshed_at = (NOW() AT TIME ZONE 'utc'),
			num_refreshs = num_refreshs+1,
			scopes = COALESCE($1::TEXT[], scopes)
		WHERE id = $2
		RETURNING sub, scopes
	`, newScopes, id).Scan(&sub, &scopes)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil, ident.ErrInvalidCredentials
		}
		return "", nil, err
	}
	return sub, scopes, err
}

func (store *Store) CreateSession(ctx context.Context, aud string, sub string, scopes []string) (sess string, grantedScopes []string, err error) {
	userId, err := uuid.Parse(sub)
	if err != nil {
		return "", nil, ident.ErrNoUser
	}
	var sessId uuid.UUID
	err = store.Pool.QueryRow(ctx, `
		INSERT INTO  "`+store.SessionsTableName+`" (sub, scopes)
		VALUES ($1, COALESCE($2, '{}'::TEXT[]))
		RETURNING id
	`, pgxResultFormatsBinary, userId.String(), scopes).Scan(&sessId)
	if err != nil {
		return "", nil, err
	}
	return sessId.String(), scopes, nil
}

func (store *Store) RevokeSession(ctx context.Context, aud string, sess string) (err error) {
	id, err := uuid.Parse(sess)
	if err != nil {
		return ident.ErrInvalidCredentials
	}

	var createdAt time.Time
	err = store.Pool.QueryRow(ctx, "DELETE FROM \""+store.SessionsTableName+"\" WHERE id=$1 RETURNING created_at", pgxResultFormatsBinary, id.String()).Scan(&createdAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return ident.ErrInvalidCredentials
		}
		return err
	}
	return nil
}
