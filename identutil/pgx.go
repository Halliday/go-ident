package identutil

import (
	"context"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/halliday/go-errors"
	"github.com/halliday/go-ident"
	"github.com/halliday/go-openid"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var pgxResultFormatsBinary = pgx.QueryResultFormats{pgx.BinaryFormatCode}

type PgxStore struct {
	Pool                  *pgxpool.Pool
	MaxNumSessionsPerUser int
	UsersTableName        string
	SessionsTableName     string
	SocialUsersTableName  string
}

func NewPgxStore(pool *pgxpool.Pool) *PgxStore {
	store := new(PgxStore)
	store.SessionsTableName = "sessions"
	store.UsersTableName = "users"
	store.SocialUsersTableName = "social_users"
	store.Pool = pool
	store.MaxNumSessionsPerUser = 8
	return store
}

var _ = ident.SessionStore((*PgxStore)(nil))
var _ = ident.UserStore((*PgxStore)(nil))

func (store *PgxStore) SetupDatabase(ctx context.Context) error {
	var steps = []func(context.Context) error{
		store.CreateExtensions,
		store.CreateTableUsers,
		store.CreateTableSocialUsers,
		store.CreateTableSessions,
	}
	for i, step := range steps {
		if err := step(ctx); err != nil {
			return errors.New("setp %d/%d: %v", i, len(steps), err)
		}
	}
	return nil
}

func (store *PgxStore) CreateExtensions(ctx context.Context) error {
	_, err := store.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS citext;`)
	return err
}

func (store *PgxStore) CreateTableUsers(ctx context.Context) error {
	_, err := store.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS "`+store.UsersTableName+`" (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			created_at timestamp NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
			updated_at timestamp NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
			num_updates integer NOT NULL DEFAULT 0,

			-- name text,
			-- given_name text,
			-- family_name text,
			-- middle_name text,
			-- nickname text,
			preferred_username text,
			preferred_username_verified bool NOT NULL DEFAULT false,
			-- profile text,
			-- picture text,
			website text,
			email citext UNIQUE,
			email_verified bool NOT NULL DEFAULT false,
			email_verified_at timestamp,
			-- gender text,
			-- birthdate text,
			-- zoneinfo text,
			locale text,
			-- phone_number text,
			-- phone_number_verified bool NOT NULL DEFAULT false,

			hashed_password text,
			password_updated_at timestamp,
			num_password_updates int NOT NULL DEFAULT 0,
			password_reset_sent_at timestamp,
			num_password_reset_sent int NOT NULL DEFAULT 0,
			password_reset_at timestamp,
			num_password_reset int NOT NULL DEFAULT 0,

			suspended bool NOT NULL DEFAULT false
		);
	`)
	return err
}

func (store *PgxStore) CreateTableSocialUsers(ctx context.Context) error {
	_, err := store.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS "`+store.SocialUsersTableName+`" (
			iss text NOT NULL,
			sub text NOT NULL,
			"user" uuid NOT NULL REFERENCES "`+store.UsersTableName+`" ON DELETE CASCADE,
			PRIMARY KEY (iss, sub)
		);
	`)
	return err
}

func (store *PgxStore) CreateTableSessions(ctx context.Context) error {
	_, err := store.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS "`+store.SessionsTableName+`" (
			id uuid NOT NULL DEFAULT gen_random_uuid(),
			sub uuid NOT NULL REFERENCES "`+store.UsersTableName+`" ON DELETE CASCADE,
			created_at timestamp NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
			refreshed_at timestamp NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
			num_refreshs integer NOT NULL DEFAULT 0,
			scopes text[] NOT NULL
		);`)
	return err
}

func (store *PgxStore) RefreshSession(ctx context.Context, aud string, sess string) (sub string, scopes []string, err error) {
	id, err := uuid.Parse(sess)
	if err != nil {
		return "", nil, ident.ErrInvalidCredentials
	}
	err = store.Pool.QueryRow(ctx, `UPDATE "`+store.SessionsTableName+`"
		SET refreshed_at = (NOW() AT TIME ZONE 'utc'), num_refreshs = num_refreshs+1
		WHERE id = $1
		RETURNING sub, scopes
	`, id).Scan(&sub, &scopes)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil, ident.ErrInvalidCredentials
		}
		return "", nil, err
	}
	return sub, scopes, err
}

func (store *PgxStore) CreateSession(ctx context.Context, aud string, sub string, scopes []string) (sess string, err error) {
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

func (store *PgxStore) RevokeSession(ctx context.Context, aud string, sess string) (err error) {
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

func (store *PgxStore) LoginUser(ctx context.Context, email string, password string, scopes ident.Scopes) (info *openid.Userinfo, grantedScopes ident.Scopes, err error) {
	info = new(openid.Userinfo)
	var pw pgtype.Text
	var id pgtype.UUID
	err = store.Pool.QueryRow(ctx, `
		SELECT id, COALESCE(preferred_username, '')::TEXT, COALESCE(email, '')::TEXT, email_verified, COALESCE(locale, '')::TEXT, hashed_password
		FROM "`+store.UsersTableName+`" WHERE email = $1`, pgxResultFormatsBinary, email).
		Scan(&id, &info.PreferredUsername, &info.Email, &info.EmailVerified, &info.Locale, &pw)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil, ident.ErrNoUser
		}
		return nil, nil, err
	}
	info.Subject = uuid.UUID(id.Bytes).String()
	if pw.Status != pgtype.Present {
		return nil, nil, e("no_password")
	}
	err = bcrypt.CompareHashAndPassword([]byte(pw.String), []byte(password))
	if err != nil {
		return nil, nil, ident.ErrInvalidCredentials
	}
	return info, scopes, nil
}

func (store *PgxStore) Userinfo(ctx context.Context, sub string) (info *openid.Userinfo, err error) {
	id, err := uuid.Parse(sub)
	if err != nil {
		return nil, ident.ErrNoUser
	}

	info = new(openid.Userinfo)
	info.Subject = sub

	err = store.Pool.QueryRow(ctx, `
		SELECT COALESCE(preferred_username, '')::TEXT, COALESCE(email, '')::TEXT, email_verified, COALESCE(locale, '')::TEXT
		FROM "`+store.UsersTableName+`"
		WHERE id = $1`, pgxResultFormatsBinary, id.String()).
		Scan(&info.PreferredUsername, &info.Email, &info.EmailVerified, &info.Locale)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ident.ErrNoUser
		}
		return nil, err
	}

	return info, err
}

func (store *PgxStore) UpdateUserPassword(ctx context.Context, sub string, password string) (err error) {
	id, err := uuid.Parse(sub)
	if err != nil {
		return ident.ErrNoUser
	}

	var hashedPassword []byte
	if password != "" {
		hashedPassword, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
	}

	var numPasswordReset int
	err = store.Pool.QueryRow(ctx, `
		UPDATE "`+store.UsersTableName+`"
		SET hashed_password = $1, password_updated_at = NOW(), num_password_updates = num_password_updates+1
		WHERE id = $2
		RETURNING num_password_updates`, pgxResultFormatsBinary, string(hashedPassword), id.String()).Scan(&numPasswordReset)

	if err != nil {
		if err == pgx.ErrNoRows {
			return ident.ErrNoUser
		}
		return err
	}

	return nil
}

func (store *PgxStore) UpdateUserEmailVerified(ctx context.Context, sub string) (err error) {
	id, err := uuid.Parse(sub)
	if err != nil {
		return ident.ErrNoUser
	}

	tag, err := store.Pool.Exec(ctx, `
		UPDATE  "`+store.UsersTableName+`"
		SET email_verified = true, email_verified_at = NOW()
		WHERE id = $1`, id.String())

	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ident.ErrNoUser
	}
	return nil
}

func (store *PgxStore) FindUserPasswordReset(ctx context.Context, email string) (info *openid.Userinfo, err error) {

	// err = store.Pool.QueryRow(ctx, `SELECT preferred_username, email, email_verified, locale FROM "`+store.TableName+`" WHERE email = $1`, email).
	// 	Scan(&info.PreferredUsername, &info.Email, &info.EmailVerified, &info.Locale)
	info = new(openid.Userinfo)
	var id pgtype.UUID
	err = store.Pool.QueryRow(ctx, `
		UPDATE "`+store.UsersTableName+`"
		SET password_reset_sent_at = NOW(), num_password_reset_sent = num_password_reset_sent
		WHERE email = $1
		RETURNING id, COALESCE(preferred_username, '')::TEXT, COALESCE(email, '')::TEXT, email_verified, COALESCE(locale, '')::TEXT;`, pgxResultFormatsBinary, email).
		Scan(&id, &info.PreferredUsername, &info.Email, &info.EmailVerified, &info.Locale)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ident.ErrNoUser
		}
		return nil, err
	}
	info.Subject = uuid.UUID(id.Bytes).String()

	return info, nil
}

func (store *PgxStore) RegisterSocialUser(ctx context.Context, iss string, info *openid.Userinfo) (sub string, err error) {
	var id uuid.UUID
	tx, err := store.Pool.Begin(ctx)
	if err != nil {
		return "", nil
	}
	rows, err := tx.Query(ctx, `
		SELECT "user"
		FROM "`+store.SocialUsersTableName+`"
		WHERE iss=$1 and sub=$2`, pgxResultFormatsBinary, iss, info.Subject)
	if err != nil {
		return "", err
	}
	if rows.Next() {
		if err := rows.Scan(&id); err != nil {
			tx.Rollback(ctx)
			return "", err
		}
		rows.Next() // drain
		tx.Commit(ctx)
		return id.String(), nil
	}

	sub, err = store.RegisterUser(ctx, info, nil)
	if err != nil {
		tx.Rollback(ctx)
		return "", err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO "`+store.SocialUsersTableName+`" (iss, sub, "user")
		VALUES ($1, $2, $3)`, iss, info.Subject, sub)
	if err != nil {
		tx.Rollback(ctx)
		return "", err
	}

	if err = tx.Commit(ctx); err != nil {
		return "", err
	}

	return sub, nil
}

func (store *PgxStore) RegisterUser(ctx context.Context, info *openid.Userinfo, password *string) (sub string, err error) {

	var b strings.Builder
	var args []interface{}
	numArgs := 0
	if info.Subject == "" {
		args = append(args, pgxResultFormatsBinary)
	}

	writeValue := func(v interface{}) (s string) {
		args = append(args, v)
		numArgs++
		s = strconv.Itoa(numArgs)
		b.WriteString(s)
		return s
	}

	b.WriteString(`INSERT INTO "`)
	b.WriteString(store.UsersTableName)
	b.WriteString(`" (`)

	if info.Subject != "" {
		b.WriteString("id, ")
	}
	b.WriteString(`preferred_username, email, email_verified, locale`)
	if password != nil {
		b.WriteString(`, hashed_password`)
	}
	b.WriteString(`)
		VALUES (`)
	if info.Subject != "" {
		b.WriteString(`$`)
		id, err := uuid.Parse(info.Subject)
		if err != nil {
			return "", err
		}
		writeValue(id.String())
		b.WriteString(`,`)
	}
	b.WriteString(`NULLIF($`)
	writeValue(info.PreferredUsername)
	b.WriteString(`, ''), NULLIF($`)
	writeValue(info.Email)
	b.WriteString(`, ''), $`)
	writeValue(info.EmailVerified)
	b.WriteString(`, NULLIF($`)
	writeValue(info.Locale)
	b.WriteString(`, '')`)
	if password != nil {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
		if err != nil {
			return "", err
		}
		b.WriteString(`, $`)
		writeValue(hashedPassword)
	}
	b.WriteString(`)`)
	if info.Subject == "" {
		b.WriteString(`
			ON CONFLICT (email) DO UPDATE SET
			preferred_username = EXCLUDED.preferred_username,
			email = EXCLUDED.email,
			email_verified = EXCLUDED.email_verified,
			locale = EXCLUDED.locale
			RETURNING id`)

		var id uuid.UUID
		err = store.Pool.QueryRow(ctx, b.String(), args...).Scan(&id)
		sub = id.String()
	} else {
		b.WriteString(`
			ON CONFLICT (id) DO UPDATE SET
				preferred_username = EXCLUDED.preferred_username,
				email = EXCLUDED.email,
				email_verified = EXCLUDED.email_verified,
				locale = EXCLUDED.locale`)

		_, err = store.Pool.Exec(ctx, b.String(), args...)
		sub = info.Subject
	}

	if err != nil {
		return "", err
	}

	return sub, nil
}

func (store *PgxStore) UpdateUser(ctx context.Context, u *ident.UserUpdate) (err error) {
	id, err := uuid.Parse(u.Subject)
	if err != nil {
		return ident.ErrNoUser
	}

	var b strings.Builder
	args := []interface{}{pgxResultFormatsBinary}
	writeValue := func(v interface{}) (s string) {
		args = append(args, v)
		s = strconv.Itoa(len(args) - 1)
		b.WriteString(s)
		return s
	}
	b.WriteString(`UPDATE "`)
	b.WriteString(store.UsersTableName)
	b.WriteString(`" SET
		updated_at = NOW(), num_updates = num_updates+1`)

	if u.NewPassword != "" {
		if u.OldPassword != "" {
			var hashedPassword []byte
			err = store.Pool.QueryRow(ctx, `
				SELECT hashed_password
				FROM "`+store.UsersTableName+`"
				WHERE id=$1`, pgxResultFormatsBinary, id).Scan(&hashedPassword)
			if err != nil {
				return err
			}
			err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(u.OldPassword))
			if err != nil {
				return e("bad_request")
			}
		}

		b.WriteString(`, hashed_password=$`)
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		writeValue(hashedPassword)
	}

	if u.PreferredUsername != "" {
		b.WriteString(`, preferred_username=$`)
		writeValue(u.PreferredUsername)
		b.WriteString(`, preferred_username_verified=`)
		if u.PreferredUsernameVerified {
			b.WriteString(`true`)
		} else {
			b.WriteString(`false`)
		}
	}

	if u.Email != "" {
		b.WriteString(`, email=$`)
		writeValue(u.Email)
		b.WriteString(`, email_verified=`)
		if u.EmailVerified {
			b.WriteString(`true`)
		} else {
			b.WriteString(`false`)
		}
	}

	if u.Locale != "" {
		b.WriteString(` locale=$`)
		writeValue(u.Locale)
	}

	b.WriteString(` WHERE id=$`)
	writeValue(id)
	b.WriteString(` RETURNING num_updates`)

	var numUpdates int
	err = store.Pool.QueryRow(ctx, b.String(), args...).Scan(&numUpdates)

	if err != nil {
		if err == pgx.ErrNoRows {
			return ident.ErrNoUser
		}
		return err
	}

	return nil
}

type FindUsersRequest struct {
	PageToken string `json:"pageToken"`
	PageSize  int    `json:"pageSize"`
	Search    string `json:"search"`
}

func (req FindUsersRequest) hasFilter() bool {
	return req.Search != ""
}

type FindUsersResponse struct {
	Users         []*User `json:"users"`
	NextPageToken string  `json:"nextPageToken,omitempty"`
	NumTotal      int     `json:"numTotal"`
	NumUsersTotal int     `json:"numUsersTotal"`
}

type User struct {
	openid.Userinfo
	Suspended bool `json:"suspended"`
	// CreatedAt time.Time
	// UpdatedAt time.Time
	Rank float64 `json:"rank,omitempty"`
}

func isSpecialCharacter(r rune) bool {
	return r == '%' || r == '_'
}

func (store *PgxStore) FindUsers(ctx context.Context, req *FindUsersRequest) (resp *FindUsersResponse, err error) {

	var b strings.Builder
	args := []interface{}{pgxResultFormatsBinary}

	writeValue := func(v interface{}) (s string) {
		args = append(args, v)
		s = strconv.Itoa(len(args) - 1)
		b.WriteString(s)
		return s
	}
	var hasWhere = false
	writeWhere := func() {
		if hasWhere {
			b.WriteString(" AND")
		} else {
			b.WriteString(" WHERE")
			hasWhere = true
		}
	}

	hasWhitespace := strings.IndexFunc(req.Search, unicode.IsSpace) != -1
	simpleSearch := req.Search != "" && !hasWhitespace
	complexSearch := req.Search != "" && !simpleSearch

	if complexSearch {
		b.WriteString(`WITH users AS (`)
	}
	b.WriteString(`
		SELECT
			u.id,
			u.created_at,
			COALESCE(u.preferred_username, '')::TEXT AS preferred_username,
			COALESCE(u.email, '')::TEXT AS email,
			u.email_verified,
			COALESCE(u.locale, '')::TEXT AS locale,
			u.updated_at,
			u.suspended`)
	if complexSearch {
		b.WriteString(`,
			( setweight(to_tsvector('english', COALESCE(u.email, '')), 'A') ||
			setweight(to_tsvector('english', COALESCE(u.preferred_username, '')), 'B')) as body`)
	}
	b.WriteString(`
		FROM "`)
	b.WriteString(store.UsersTableName)
	b.WriteString(`" u`)
	if complexSearch {
		b.WriteString(`)
		SELECT
			u.id,
			u.created_at,
			u.preferred_username,
			u.email,
			u.email_verified,
			u.locale,
			u.updated_at,
			u.suspended,
			ts_rank_cd(u.body, query, 32) AS rank
		FROM
			websearch_to_tsquery ('english', $`)
		writeValue(req.Search)
		b.WriteString(`) query,
			users u`)
	}
	if req.PageToken != "" {
		userId, err := uuid.Parse(req.PageToken)
		if err != nil {
			return nil, e("bad_pagetoken", err)
		}
		b.WriteString(`,
			(SELECT created_at, id from users WHERE id = $`)
		writeValue(userId.String())
		b.WriteString(`) as page
			`)
		writeWhere()
		if complexSearch {
			b.WriteString(` (u.rank, u.id) > (page.rank, page.id)`)
		} else {
			b.WriteString(` (u.created_at, u.id) < (page.created_at, page.id)`)
		}
	}
	if simpleSearch {
		writeWhere()
		b.WriteString(` (u.email ILIKE $`)
		search := req.Search
		if strings.IndexFunc(req.Search, isSpecialCharacter) == -1 {
			search = "%" + search + "%"
		}
		arg := writeValue(search)
		b.WriteString(` OR u.preferred_username ILIKE $`)
		b.WriteString(arg)
		b.WriteString(`)`)

	}
	if complexSearch {
		writeWhere()
		b.WriteString(` u.body @@ query
			ORDER BY rank ASC
		`)
	} else {
		b.WriteString(` ORDER BY (u.created_at, u.id) DESC`)
	}

	if req.PageSize > 0 {
		b.WriteString(`
			LIMIT $`)
		writeValue(req.PageSize)
	}

	rows, err := store.Pool.Query(ctx, b.String(), args...)
	if err != nil {
		return nil, err
	}

	resp = new(FindUsersResponse)
	resp.Users = make([]*User, 0, 8)

	for rows.Next() {
		user := new(User)
		var id pgtype.UUID
		var createdAt pgtype.Timestamp
		var updatedAt pgtype.Timestamp
		var _args [9]interface{}
		args := _args[0:8]
		args[0] = &id
		args[1] = &createdAt
		args[2] = &user.PreferredUsername
		args[3] = &user.Email
		args[4] = &user.EmailVerified
		args[5] = &user.Locale
		args[6] = &updatedAt
		args[7] = &user.Suspended
		if complexSearch {
			args = append(args, &user.Rank)
		}
		err = rows.Scan(args...)
		if err != nil {
			return nil, err
		}
		user.CreatedAt = createdAt.Time.Unix()
		user.UpdatedAt = updatedAt.Time.Unix()

		user.Subject = uuid.UUID(id.Bytes).String()
		resp.Users = append(resp.Users, user)
	}

	if req.PageSize > 0 && len(resp.Users) == req.PageSize {
		lastItem := resp.Users[len(resp.Users)-1]
		nextPageToken := lastItem.Subject
		resp.NextPageToken = nextPageToken
	}

	if req.hasFilter() {
		err = store.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM "`+store.UsersTableName+`"`).Scan(&resp.NumUsersTotal)
		if err != nil {
			return nil, err
		}

		b.Reset()
		args = []interface{}{pgxResultFormatsBinary}

		b.WriteString(`SELECT COUNT(*) FROM "`)
		b.WriteString(store.UsersTableName)
		b.WriteString(`" u`)
		if simpleSearch {
			b.WriteString(` WHERE u.email ILIKE $`)
			search := req.Search
			if strings.IndexFunc(req.Search, isSpecialCharacter) == -1 {
				search = "%" + search + "%"
			}
			arg := writeValue(search)
			b.WriteString(` OR u.preferred_username ILIKE $`)
			b.WriteString(arg)
		}
		if complexSearch {
			b.WriteString(`, websearch_to_tsquery ('english', $`)
			writeValue(req.Search)
			b.WriteString(`) query
				WHERE ( setweight(to_tsvector('english', COALESCE(u.email, '')), 'A') ||
				setweight(to_tsvector('english', COALESCE(u.preferred_username, '')), 'B')) @@ query`)
		}
		err = store.Pool.QueryRow(ctx, b.String(), args...).Scan(&resp.NumTotal)
		if err != nil {
			return nil, err
		}
	} else {

		if req.PageToken == "" && resp.NextPageToken == "" {
			resp.NumTotal = len(resp.Users)
			resp.NumUsersTotal = resp.NumTotal
		} else {

			err = store.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM "`+store.UsersTableName+`"`).Scan(&resp.NumUsersTotal)
			if err != nil {
				return nil, err
			}
			resp.NumTotal = resp.NumUsersTotal
		}
	}

	return resp, nil
}

////////////////////////////////////////////////////////////////////////////////

type SetUsersEmailVerified struct {
	Users    []string `json:"users"`
	Verified bool     `json:"verified"`
}

type SetUsersEmailVerifiedResponse struct {
	NumUsers int `json:"numUsers"`
}

func (store *PgxStore) SetUsersEmailVerified(ctx context.Context, req *SetUsersEmailVerified) (resp *SetUsersEmailVerifiedResponse, err error) {
	resp = new(SetUsersEmailVerifiedResponse)
	if len(req.Users) == 0 {
		return resp, nil
	}
	var b strings.Builder
	b.WriteString(`UPDATE "`)
	b.WriteString(store.UsersTableName)
	b.WriteString(`"
		SET email_verified = $1
		WHERE id = ANY($2)`)
	tag, err := store.Pool.Exec(ctx, b.String(), req.Verified, req.Users)
	if err != nil {
		return nil, err
	}
	resp.NumUsers = int(tag.RowsAffected())
	return resp, err
}

////////////////////////////////////////////////////////////////////////////////

type SuspendUsersRequest struct {
	Users    []string `json:"users"`
	AllUsers bool     `json:"allUsers"`
}

type SuspendUsersResponse struct {
	NumUsers int `json:"numUsers"`
}

func (store *PgxStore) SuspendUsers(ctx context.Context, req *SuspendUsersRequest) (resp *SuspendUsersResponse, err error) {

	var b strings.Builder
	var args []interface{}

	if req.AllUsers {

		b.WriteString(`UPDATE "`)
		b.WriteString(store.UsersTableName)
		b.WriteString(`" SET suspended = true WHERE id = ANY($1)`)
	} else {

		var ids pgtype.UUIDArray
		err = ids.Set(req.Users)
		if err != nil {
			return nil, nil
		}
		b.WriteString(`UPDATE "`)
		b.WriteString(store.UsersTableName)
		b.WriteString(`" SET suspended = true WHERE id = ANY($1)`)
		args = []interface{}{ids}
	}

	tag, err := store.Pool.Exec(ctx, b.String(), args...)
	if err != nil {
		return nil, err
	}

	resp = new(SuspendUsersResponse)
	resp.NumUsers = int(tag.RowsAffected())
	l.Info("users_suspended", resp.NumUsers)
	return resp, err
}

//

type ReleaseUsersRequest struct {
	Users    []string `json:"users"`
	AllUsers bool     `json:"allUsers"`
}

type ReleaseUsersResponse struct {
	NumUsers int `json:"numUsers"`
}

func (store *PgxStore) ReleaseUsers(ctx context.Context, req *ReleaseUsersRequest) (resp *ReleaseUsersResponse, err error) {
	var b strings.Builder
	var args []interface{}

	if req.AllUsers {

		b.WriteString(`UPDATE "`)
		b.WriteString(store.UsersTableName)
		b.WriteString(`" SET suspended = true WHERE id = ANY($1)`)
	} else {

		var ids pgtype.UUIDArray
		err = ids.Set(req.Users)
		if err != nil {
			return nil, nil
		}
		b.WriteString(`UPDATE "`)
		b.WriteString(store.UsersTableName)
		b.WriteString(`" SET suspended = false WHERE id = ANY($1)`)
		args = []interface{}{ids}
	}

	tag, err := store.Pool.Exec(ctx, b.String(), args...)
	if err != nil {
		return nil, err
	}

	resp = new(ReleaseUsersResponse)
	resp.NumUsers = int(tag.RowsAffected())
	l.Info("users_released", resp.NumUsers)
	return resp, err
}

//

// type DeleteUsersRequest struct {
// 	Users []string `json:"users"`
// }

// type DeleteUsersResponse struct {
// 	NumUsers int `json:"numUsers"`
// }

// func (store *PgxStore) DeleteUsers(ctx context.Context, req *DeleteUsersRequest) (resp *DeleteUsersResponse, err error) {
// 	var b strings.Builder
// 	var args []interface{}

// 	// if req.AllUsers {

// 	// 	b.WriteString(`UPDATE "`)
// 	// 	b.WriteString(store.UsersTableName)
// 	// 	b.WriteString(`" SET suspended = true WHERE id = ANY($1)`)
// 	// } else {

// 	var ids pgtype.UUIDArray
// 	err = ids.Set(req.Users)
// 	if err != nil {
// 		return nil, nil
// 	}
// 	b.WriteString(`DELETE FROM "`)
// 	b.WriteString(store.UsersTableName)
// 	b.WriteString(`" WHERE id = ANY($1)`)
// 	args = []interface{}{ids}
// 	// }

// 	tag, err := store.Pool.Exec(ctx, b.String(), args...)
// 	if err != nil {
// 		return nil, err
// 	}

// 	resp = new(DeleteUsersResponse)
// 	resp.NumUsers = int(tag.RowsAffected())
// 	l.Info("users_deleted", resp.NumUsers)
// 	return resp, err
// }

//

func (store *PgxStore) SetUserPassword(ctx context.Context, user UserId, password string) (err error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	tag, err := store.Pool.Exec(ctx, `UPDATE "`+store.UsersTableName+`" SET hashed_password = $1 WHERE id = $2`, hashedPassword, user)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ident.ErrNoUser
	}
	return err
}

func (store *PgxStore) DeleteUsers(ctx context.Context, user []string) (numDeleted int, err error) {
	var ids pgtype.UUIDArray
	if err = ids.Set(user); err != nil {
		return 0, nil
	}
	tag, err := store.Pool.Exec(ctx, `DELETE FORM "`+store.UsersTableName+`"  WHERE id = ANY($1)`, ids, user)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() == 0 {
		return 0, ident.ErrNoUser
	}
	return int(tag.RowsAffected()), err
}
