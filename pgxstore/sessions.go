package pgxstore

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/halliday/go-ident"
	"github.com/jackc/pgx/v4"
)

func (store *Store) RefreshSession(ctx context.Context, sess string, filterScopes []string) (sub string, grantedScopes []string, err error) {
	id, err := uuid.Parse(sess)
	if err != nil {
		return "", nil, ident.ErrInvalidCredentials
	}
	var b pgxBuilder
	b.resultFormatsBinary()
	b.WriteString(`UPDATE "`)
	b.WriteString(store.SessionsTableName)
	b.WriteString(`"
		SET
			refreshed_at = (NOW() AT TIME ZONE 'utc'),
			num_refreshs = num_refreshs+1`)
	if filterScopes != nil {
		b.WriteString(`, scopes = ARRAY(SELECT scope FROM unnest(scopes`)
		b.WriteString(`) scope WHERE scope = ANY(`)
		b.WriteValue(filterScopes)
		b.WriteString(`::TEXT[]`)
		b.WriteString(`))`)
	}
	b.WriteString(`
		WHERE id = `)
	b.WriteValue(id)
	b.WriteString(`
		RETURNING sub, scopes`)

	err = store.Pool.QueryRow(ctx, b.String(), b.args...).Scan(&sub, &grantedScopes)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil, ident.ErrInvalidCredentials
		}
		return "", nil, err
	}
	return sub, grantedScopes, err
}

func (store *Store) CreateSession(ctx context.Context, aud string, sub string, scopes []string) (sess string, err error) {
	userId, err := uuid.Parse(sub)
	if err != nil {
		return "", ident.ErrNoUser
	}
	var sessId uuid.UUID
	err = store.Pool.QueryRow(ctx, `
		INSERT INTO  "`+store.SessionsTableName+`" (sub, scopes)
		VALUES ($1, COALESCE($2, '{}'::TEXT[]))
		RETURNING id
	`, pgxResultFormatsBinary, userId.String(), scopes).Scan(&sessId)
	if err != nil {
		return "", err
	}
	return sessId.String(), nil
}

func (store *Store) RevokeSession(ctx context.Context, sess string) (err error) {
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

func (store *Store) UpdateSessions(ctx context.Context, sess string, sub string, addScopes []string, removeScopes []string) (numUpdated int, err error) {

	if len(addScopes) == 0 && len(removeScopes) == 0 {
		return 0, nil
	}
	if sess == "" && sub == "" {
		return 0, nil
	}

	var b pgxBuilder
	b.WriteString(`UPDATE "`)
	b.WriteString(store.SessionsTableName)
	b.WriteString(`"
		SET
			refreshed_at = (NOW() AT TIME ZONE 'utc'),
			num_refreshs = num_refreshs+1`)
	if removeScopes != nil {
		b.WriteString(`, scopes = ARRAY(SELECT DISTINCT scope FROM unnest(scopes`)
		if len(addScopes) > 0 {
			b.WriteString(` || `)
			b.WriteValue(addScopes)
			b.WriteString(`::TEXT[]`)
		}
		b.WriteString(`) scope WHERE scope <> ANY(`)
		b.WriteValue(removeScopes)
		b.WriteString(`::TEXT[]))`)
	} else /* if len(addScopes) > 0 */ {
		b.WriteString(`, scopes = ARRAY(SELECT DISTINCT scope FROM unnest(scopes ||`)
		b.WriteValue(addScopes)
		b.WriteString(`::TEXT[]) scope)`)
	}

	b.WriteString(`
		WHERE`)

	if sess != "" {
		b.WriteString(` id = `)
		id, err := uuid.Parse(sess)
		if err != nil {
			return 0, ident.ErrInvalidCredentials
		}
		b.WriteValue(id)
	} else /* if sub != "" */ {
		b.WriteString(` sub = `)
		id, err := uuid.Parse(sub)
		if err != nil {
			return 0, ident.ErrInvalidCredentials
		}
		b.WriteValue(id)
	}

	tag, err := store.Pool.Exec(ctx, b.String(), b.args...)
	if err != nil {
		return 0, err
	}
	numUpdated = int(tag.RowsAffected())

	return numUpdated, nil
}
