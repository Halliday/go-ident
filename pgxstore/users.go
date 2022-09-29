package pgxstore

import (
	"context"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/halliday/go-ident"
	"github.com/halliday/go-ident/pgxstore/pgtools"
	"github.com/halliday/go-openid"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"golang.org/x/crypto/bcrypt"
)

func (store *Store) LoginUser(ctx context.Context, email string, password string) (sub string, err error) {
	var pw pgtype.Text
	var id pgtype.UUID
	err = store.Pool.QueryRow(ctx, `
		SELECT id, hashed_password
		FROM "`+store.UsersTableName+`" WHERE email = $1`, pgxResultFormatsBinary, email).
		Scan(&id, &pw)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", ident.ErrNoUser
		}
		return "", err
	}
	if pw.Status != pgtype.Present {
		return "", e("no_password")
	}
	err = bcrypt.CompareHashAndPassword([]byte(pw.String), []byte(password))
	if err != nil {
		return "", ident.ErrInvalidCredentials
	}
	sub = uuid.UUID(id.Bytes).String()
	return sub, nil
}

func (store *Store) Userinfo(ctx context.Context, sub string) (info *openid.Userinfo, err error) {
	id, err := uuid.Parse(sub)
	if err != nil {
		return nil, ident.ErrNoUser
	}

	info = new(openid.Userinfo)
	info.Subject = sub
	var b pgxBuilder
	b.resultFormatsBinary()
	b.WriteString(`
	SELECT
		COALESCE(preferred_username, '')::TEXT,
		COALESCE(email, '')::TEXT, email_verified,
		COALESCE(locale, '')::TEXT,
		ARRAY(SELECT ROW(iss, profile, picture, website) FROM "`)
	b.WriteString(store.SocialUsersTableName)
	b.WriteString(`" WHERE "user" = id)
		FROM "`)
	b.WriteString(store.UsersTableName)
	b.WriteString(`"
		WHERE id = `)
	b.WriteValue(id.String())
	err = store.Pool.QueryRow(ctx, b.String(), b.args...).
		Scan(&info.PreferredUsername, &info.Email, &info.EmailVerified, &info.Locale, (*socialProviders)(&info.SocialProviders))

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ident.ErrNoUser
		}
		return nil, err
	}

	return info, err
}

type socialProviders []*openid.SocialProvider
type socialProvider openid.SocialProvider

func (s *socialProviders) DecodeBinary(ci *pgtype.ConnInfo, src []byte) error {
	d, err := pgtools.NewArrayDecoder(ci, src)
	if err != nil {
		return err
	}
	*s = make([]*openid.SocialProvider, d.Len)
	i := 0
	for d.Next() {
		p := new(openid.SocialProvider)
		if err := d.Decode((*socialProvider)(p)); err != nil {
			return err
		}
		(*s)[i] = p
		i++
	}
	return nil
}

func (s *socialProvider) DecodeBinary(ci *pgtype.ConnInfo, src []byte) error {
	var iss pgtype.Text
	var profile pgtype.Text
	var picture pgtype.Text
	var website pgtype.Text
	err := pgtools.ScanDecoders(ci, src, &iss, &profile, &picture, &website)
	if err != nil {
		return err
	}
	s.Issuer = iss.String
	s.Profile = profile.String
	s.Picture = picture.String
	s.Website = website.String
	return nil
}

func (store *Store) UpdateUserPassword(ctx context.Context, sub string, password string) (err error) {
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

func (store *Store) RegisterSocialUsers(ctx context.Context, iss string, users []*ident.User) (subs []string, err error) {
	if len(users) == 0 {
		return nil, nil
	}

	subs = make([]string, len(users))
	for i, user := range users {
		subs[i] = user.Subject + "@" + iss
	}
	var b strings.Builder
	b.WriteString(`
		SELECT "user" FROM unnest($1::TEXT[]) WITH ORDINALITY as elm(sub_iss, idx)
		LEFT JOIN "`)
	b.WriteString(store.SocialUsersTableName)
	b.WriteString(`" ON sub || '@' || iss = sub_iss
		ORDER BY idx ASC`)
	rows, err := store.Pool.Query(ctx, b.String(), pgxResultFormatsBinary, subs)
	if err != nil {
		return nil, err
	}

	unregisteredUsers := make([]*ident.User, 0, len(users))
	unregisteredUsersIdx := make([]int, 0, len(users))

	// ids := make([]pgtype.UUID, len(users))
	i := 0
	for rows.Next() {
		var id pgtype.UUID
		err = rows.Scan(&id)
		if err != nil {
			return nil, err
		}
		if id.Status == pgtype.Present {
			subs[i] = uuid.UUID(id.Bytes).String()
		} else {
			unregisteredUsers = append(unregisteredUsers, users[i])
			unregisteredUsersIdx = append(unregisteredUsersIdx, i)
		}
		// ids[i] = id
		i++
	}

	if len(unregisteredUsers) > 0 {
		remoteIds := make([]string, len(unregisteredUsers))

		profiles := pgtype.TextArray{
			Elements:   make([]pgtype.Text, len(unregisteredUsers)),
			Dimensions: []pgtype.ArrayDimension{{Length: int32(len(unregisteredUsers)), LowerBound: 1}},
			Status:     pgtype.Present,
		}
		pictures := pgtype.TextArray{
			Elements:   make([]pgtype.Text, len(unregisteredUsers)),
			Dimensions: []pgtype.ArrayDimension{{Length: int32(len(unregisteredUsers)), LowerBound: 1}},
			Status:     pgtype.Present,
		}
		websites := pgtype.TextArray{
			Elements:   make([]pgtype.Text, len(unregisteredUsers)),
			Dimensions: []pgtype.ArrayDimension{{Length: int32(len(unregisteredUsers)), LowerBound: 1}},
			Status:     pgtype.Present,
		}

		for i, user := range unregisteredUsers {

			remoteIds[i] = user.Subject
			if user.Profile != "" {
				profiles.Elements[i] = pgtype.Text{String: user.Profile, Status: pgtype.Present}
			} else {
				profiles.Elements[i] = pgtype.Text{Status: pgtype.Null}
			}
			if user.Picture != "" {
				pictures.Elements[i] = pgtype.Text{String: user.Picture, Status: pgtype.Present}
			} else {
				pictures.Elements[i] = pgtype.Text{Status: pgtype.Null}
			}
			if user.Website != "" {
				websites.Elements[i] = pgtype.Text{String: user.Website, Status: pgtype.Present}
			} else {
				websites.Elements[i] = pgtype.Text{Status: pgtype.Null}
			}

			user.Subject = ""
		}

		newRegisteredSubs, err := store.RegisterUsers(ctx, "", true, unregisteredUsers)
		if err != nil {
			return nil, err
		}

		ids := pgtype.UUIDArray{
			Elements:   make([]pgtype.UUID, len(unregisteredUsers)),
			Dimensions: []pgtype.ArrayDimension{{Length: int32(len(unregisteredUsers)), LowerBound: 1}},
			Status:     pgtype.Present,
		}

		for j, idx := range unregisteredUsersIdx {
			subs[idx] = newRegisteredSubs[j]
			ids.Elements[j] = pgtype.UUID{Bytes: uuid.MustParse(newRegisteredSubs[j]), Status: pgtype.Present}

		}

		var b strings.Builder
		b.WriteString(`
			INSERT INTO "`)
		b.WriteString(store.SocialUsersTableName)
		b.WriteString(`" ("user", iss, sub, profile, picture, website)
			SELECT "user", $1, sub, profile, picture, website FROM unnest($2::UUID[], $3::TEXT[], $4::TEXT[], $5::TEXT[], $6::TEXT[]) record_user_sub("user", sub, profile, picture, website)`)
		_, err = store.Pool.Exec(ctx, b.String(), iss, ids, remoteIds, profiles, pictures, websites)
		if err != nil {
			return nil, err
		}
	}

	return subs, nil
}

var localeRegexp = regexp.MustCompile(`^[a-zA-Z]{2}([_-][a-zA-Z]{2})?$`)

func (store *Store) RegisterUsers(ctx context.Context, iss string, ignoreEmails bool, users []*ident.User) (subs []string, err error) {

	if iss != "" {
		return store.RegisterSocialUsers(ctx, iss, users)
	}

	var b pgxBuilder
	b.resultFormatsBinary()

	subs = make([]string, len(users))

	b.WriteString(`WITH elm AS (
			SELECT * FROM unnest(`)

	ids := pgtype.UUIDArray{
		Elements:   make([]pgtype.UUID, len(users)),
		Dimensions: []pgtype.ArrayDimension{{Length: int32(len(users)), LowerBound: 1}},
		Status:     pgtype.Present,
	}
	preferredUsernames := pgtype.TextArray{
		Elements:   make([]pgtype.Text, len(users)),
		Dimensions: []pgtype.ArrayDimension{{Length: int32(len(users)), LowerBound: 1}},
		Status:     pgtype.Present,
	}
	emails := pgtype.TextArray{
		Elements:   make([]pgtype.Text, len(users)),
		Dimensions: []pgtype.ArrayDimension{{Length: int32(len(users)), LowerBound: 1}},
		Status:     pgtype.Present,
	}
	emailVerifieds := pgtype.BoolArray{
		Elements:   make([]pgtype.Bool, len(users)),
		Dimensions: []pgtype.ArrayDimension{{Length: int32(len(users)), LowerBound: 1}},
		Status:     pgtype.Present,
	}
	locales := pgtype.BPCharArray{
		Elements:   make([]pgtype.BPChar, len(users)),
		Dimensions: []pgtype.ArrayDimension{{Length: int32(len(users)), LowerBound: 1}},
		Status:     pgtype.Present,
	}
	hashedPasswords := pgtype.ByteaArray{
		Elements:   make([]pgtype.Bytea, len(users)),
		Dimensions: []pgtype.ArrayDimension{{Length: int32(len(users)), LowerBound: 1}},
		Status:     pgtype.Present,
	}

	for i, u := range users {
		if u.Subject != "" {
			id, err := uuid.Parse(u.Subject)
			if err != nil {
				return nil, err
			}
			ids.Elements[i] = pgtype.UUID{Bytes: id, Status: pgtype.Present}
			subs[i] = u.Subject
		} else {
			id := uuid.New()
			ids.Elements[i] = pgtype.UUID{Bytes: id, Status: pgtype.Present}
			subs[i] = id.String()
		}

		if u.PreferredUsername != "" {
			preferredUsernames.Elements[i] = pgtype.Text{String: u.PreferredUsername, Status: pgtype.Present}
		} else {
			preferredUsernames.Elements[i] = pgtype.Text{Status: pgtype.Null}
		}

		if u.Email != "" {
			emails.Elements[i] = pgtype.Text{String: u.Email, Status: pgtype.Present}
		} else {
			emails.Elements[i] = pgtype.Text{Status: pgtype.Null}
		}

		emailVerifieds.Elements[i] = pgtype.Bool{Bool: u.EmailVerified, Status: pgtype.Present}

		locale := formatLocale(u.Locale)
		// errors are dropped silently
		if locale != "" {
			locales.Elements[i] = pgtype.BPChar{String: u.Locale, Status: pgtype.Present}
		} else {
			locales.Elements[i] = pgtype.BPChar{Status: pgtype.Null}
		}

		if u.Password.Valid {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password.Value), bcrypt.DefaultCost)
			if err != nil {
				return nil, err
			}
			hashedPasswords.Elements[i] = pgtype.Bytea{Bytes: hashedPassword, Status: pgtype.Present}
		} else {
			hashedPasswords.Elements[i] = pgtype.Bytea{Status: pgtype.Null}
		}
	}

	b.WriteValue(ids)
	b.WriteString(`::uuid[], `)
	b.WriteValue(preferredUsernames)
	b.WriteString(`::text[], `)
	b.WriteValue(emails)
	b.WriteString(`::text[], `)
	b.WriteValue(emailVerifieds)
	b.WriteString(`::bool[], `)
	b.WriteValue(locales)
	b.WriteString(`::char(5)[], `)
	b.WriteValue(hashedPasswords)
	b.WriteString(`::bytea[]) WITH ORDINALITY elm(id, preferred_username, email, email_verified, locale, hashed_password, idx)
		),
		registered_users AS (
			SELECT idx, users.id FROM "`)
	b.WriteString(store.UsersTableName)
	b.WriteString(`" as users
			JOIN elm ON elm.email = users.email 
		),
		insert AS (
			INSERT INTO "`)
	b.WriteString(store.UsersTableName)
	b.WriteString(`" (id, preferred_username, email, email_verified, locale, hashed_password)
			SELECT elm.id, preferred_username, email, email_verified, locale, hashed_password FROM elm
			LEFT JOIN registered_users ON registered_users.idx = elm.idx
			WHERE registered_users.idx IS NULL
			ON CONFLICT (id) DO NOTHING
			RETURNING id
		)
		SELECT COALESCE(registered_users.id, elm.id) FROM elm
		LEFT JOIN registered_users ON registered_users.idx = elm.idx
		ORDER BY elm.idx ASC`)

	rows, err := store.Pool.Query(ctx, b.String(), b.args...)
	if err != nil {
		return nil, err
	}

	duplicateEmails := 0

	i := 0
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		sub := id.String()
		if sub != subs[i] {
			duplicateEmails++
			subs[i] = sub
		}
		i++
	}

	if !ignoreEmails {
		if duplicateEmails != 0 {
			return nil, e("email_already_registered")
		}
	}

	return subs, nil
}

func (store *Store) UpdateUsers(ctx context.Context, sel ident.Selection, u *ident.UserUpdate) (numUpdated int, err error) {
	if sel.Empty() {
		return 0, nil
	}
	// id, err := uuid.Parse(u.Subject)
	// if err != nil {
	// 	return ident.ErrNoUser
	// }

	var b pgxBuilder

	// var b strings.Builder
	// args := []interface{}{pgxResultFormatsBinary}
	// writeValue := func(v interface{}) (s string) {
	// 	args = append(args, v)
	// 	s = strconv.Itoa(len(args) - 1)
	// 	b.WriteString(s)
	// 	return s
	// }
	b.WriteString(`UPDATE "`)
	b.WriteString(store.UsersTableName)
	b.WriteString(`" SET
		updated_at = NOW(), num_updates = num_updates+1`)

	if u.NewPassword.Valid {
		if u.OldPassword.Valid {

			if sel.All || len(sel.Ids) != 1 || sel.Email != "" || sel.Search != "" {
				return 0, e("bad_selection")
			}
			id := sel.Ids[0]

			var hashedPassword []byte
			err = store.Pool.QueryRow(ctx, `
				SELECT hashed_password
				FROM "`+store.UsersTableName+`"
				WHERE id=$1`, pgxResultFormatsBinary, id).Scan(&hashedPassword)
			if err != nil {
				return 0, err
			}
			err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(u.OldPassword.Value))
			if err != nil {
				return 0, e("bad_request")
			}
		}

		b.WriteString(`, hashed_password=`)
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.NewPassword.Value), bcrypt.DefaultCost)
		if err != nil {
			return 0, err
		}
		b.WriteValue(hashedPassword)
	}

	maybeAdd := func(name string, valid bool, value any) {
		if valid {
			b.WriteString(`, ` + name + `=`)
			b.WriteValue(value)
		}
	}

	maybeAdd(`preferred_username`, u.Name.Valid, u.Name.Value)
	maybeAdd(`preferred_username`, u.GivenName.Valid, u.GivenName.Value)
	maybeAdd(`preferred_username`, u.FamilyName.Valid, u.FamilyName.Value)
	maybeAdd(`preferred_username`, u.MiddleName.Valid, u.MiddleName.Value)
	maybeAdd(`preferred_username`, u.Nickname.Valid, u.Nickname.Value)

	maybeAdd("name", u.Name.Valid, u.Name.Value)
	maybeAdd("given_name", u.GivenName.Valid, u.GivenName.Value)
	maybeAdd("family_name", u.FamilyName.Valid, u.FamilyName.Value)
	maybeAdd("middle_name", u.MiddleName.Valid, u.MiddleName.Value)
	maybeAdd("nickname", u.Nickname.Valid, u.Nickname.Value)

	maybeAdd("preferred_username", u.PreferredUsername.Valid, u.PreferredUsername.Value)
	// requires priviliged scope
	maybeAdd("preferred_username_verified", u.PreferredUsernameVerified.Valid, u.PreferredUsernameVerified.Value)

	// maybeAdd("profile", u.Profile.Valid, u.Profile.Value)
	// maybeAdd("picture", u.Picture.Valid, u.Picture.Value)
	// maybeAdd("website", u.Website.Valid, u.Website.Value)

	maybeAdd("email", u.Email.Valid, u.Email.Value)
	// requires priviliged scope
	maybeAdd("email_verified", u.EmailVerified.Valid, u.EmailVerified.Value)

	maybeAdd("gender", u.Gender.Valid, u.Gender.Value)
	maybeAdd("birthdat", u.Birthdate.Valid, u.Birthdate.Value)
	maybeAdd("zoneinfo", u.Zoneinfo.Valid, u.Zoneinfo.Value)
	maybeAdd("locale", u.Locale.Valid, u.Locale.Value)
	maybeAdd("phone_number", u.PhoneNumber.Valid, u.PhoneNumber.Value)
	// requires priviliged scope
	maybeAdd("phone_number_verified", u.PhoneNumberVerified.Valid, u.PhoneNumberVerified.Value)

	if u.Address != nil {
		// TODO
	}

	// requires priviliged scope
	maybeAdd("suspended", u.Suspended.Valid, u.Suspended.Value)

	b.WriteSelection(sel)

	tag, err := store.Pool.Exec(ctx, b.String(), b.args...)
	if err != nil {
		if pgConnErr, ok := err.(*pgconn.PgError); ok {
			if pgConnErr.Code == "23505" && pgConnErr.ConstraintName == store.UsersTableName+"_email_key" {
				return 0, e("email_already_registered")
			}
		}
		return 0, err
	}
	numUpdated = int(tag.RowsAffected())
	return numUpdated, nil
}

func formatLocale(locale string) string {
	if !localeRegexp.MatchString(locale) {
		return ""
	}
	l := strings.ToLower(locale[0:2])
	if len(locale) > 2 {
		l += "_" + strings.ToUpper(locale[3:5])
	}
	return l
}

////////////////////////////////////////////////////////////////////////////////

func (store *Store) CountUsers(ctx context.Context, sel ident.Selection) (numSel int, numTotal int, err error) {

	var b pgxBuilder
	b.resultFormatsBinary()

	b.WriteString(`SELECT COUNT(*) FROM "`)
	b.WriteString(store.UsersTableName)
	b.WriteString(`" `)
	b.WriteSelection(sel)

	err = store.Pool.QueryRow(ctx, b.String(), b.args...).Scan(&numSel)
	if err != nil {
		return 0, 0, err
	}

	return numSel, numTotal, nil
}

////////////////////////////////////////////////////////////////////////////////

func (store *Store) DeleteUsers(ctx context.Context, sel ident.Selection) (count int, err error) {

	var b pgxBuilder

	b.WriteString(`DELETE FROM "`)
	b.WriteString(store.UsersTableName)
	b.WriteString(`" `)
	b.WriteSelection(sel)

	err = store.Pool.QueryRow(ctx, b.String(), b.args...).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

////////////////////////////////////////////////////////////////////////////////

func isSpecialCharacter(r rune) bool {
	return r == '%' || r == '_'
}

func (store *Store) FindUsers(ctx context.Context, sel ident.Selection, pageToken string, pageSize int) (users []*ident.User, nextPageToken string, err error) {

	var b pgxBuilder
	b.resultFormatsBinary()

	var hasWhere = false
	writeWhere := func() {
		if hasWhere {
			b.WriteString(" AND")
		} else {
			b.WriteString(" WHERE")
			hasWhere = true
		}
	}

	hasWhitespace := strings.IndexFunc(sel.Search, unicode.IsSpace) != -1
	simpleSearch := sel.Search != "" && !hasWhitespace
	complexSearch := sel.Search != "" && !simpleSearch

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
			websearch_to_tsquery ('english', `)
		b.WriteValue(sel.Search)
		b.WriteString(`) query,
			users u`)
	}
	if pageToken != "" {
		userId, err := uuid.Parse(pageToken)
		if err != nil {
			return nil, "", e("bad_pagetoken", err)
		}
		b.WriteString(`,
			(SELECT created_at, id from users WHERE id = `)
		b.WriteValue(userId.String())
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
		b.WriteString(` (u.email ILIKE `)
		search := sel.Search
		if strings.IndexFunc(sel.Search, isSpecialCharacter) == -1 {
			search = "%" + search + "%"
		}
		searchArg := b.WriteValue(search)
		b.WriteString(` OR u.preferred_username ILIKE `)
		b.WriteString(searchArg)
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

	if pageSize > 0 {
		b.WriteString(`
			LIMIT `)
		b.WriteValue(pageSize)
	}

	rows, err := store.Pool.Query(ctx, b.String(), b.args...)
	if err != nil {
		return nil, "", err
	}

	users = make([]*ident.User, 0, 8)

	for rows.Next() {
		user := new(ident.User)
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
			var rank float32
			args = append(args, &rank)
		}
		err = rows.Scan(args...)
		if err != nil {
			return nil, "", err
		}
		user.CreatedAt = createdAt.Time.Unix()
		user.UpdatedAt = updatedAt.Time.Unix()

		user.Subject = uuid.UUID(id.Bytes).String()
		users = append(users, user)
	}

	if pageSize > 0 && len(users) == pageSize {
		lastItem := users[len(users)-1]
		nextPageToken = lastItem.Subject
	}

	return users, nextPageToken, nil
}
