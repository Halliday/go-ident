package pgxstore

import (
	"context"

	"github.com/halliday/go-errors"
)

func (store *Store) SetupDatabase(ctx context.Context) error {
	var steps = []func(context.Context) error{
		store.CreateExtensions,
		store.CreateTableUsers,
		store.CreateTableSocialUsers,
		store.CreateTableSessions,
	}
	for i, step := range steps {
		if err := step(ctx); err != nil {
			return errors.New("setup %d/%d: %v", i, len(steps), err)
		}
	}
	return nil
}

func (store *Store) CreateExtensions(ctx context.Context) error {
	_, err := store.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS citext;`)
	return err
}

func (store *Store) CreateTableUsers(ctx context.Context) error {
	_, err := store.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS "`+store.UsersTableName+`" (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			created_at timestamp NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),

			name text,
			given_name text,
			family_name text,
			middle_name text,
			nickname text,

			preferred_username text,
			preferred_username_verified bool NOT NULL DEFAULT false,

			-- profile text,
			-- picture text,
			-- website text,
			
			email citext UNIQUE,
			email_verified bool NOT NULL DEFAULT false,
			email_verified_at timestamp,
			
			gender text,
			birthdate date,
			zoneinfo text,
			locale char(5),
			phone_number text,
			phone_number_verified bool NOT NULL DEFAULT false,

			hashed_password bytea,
			password_updated_at timestamp,
			-- num_password_updates int NOT NULL DEFAULT 0,
			-- password_reset_sent_at timestamp,
			-- num_password_reset_sent int NOT NULL DEFAULT 0,
			-- password_reset_at timestamp,
			-- num_password_reset int NOT NULL DEFAULT 0,

			suspended bool NOT NULL DEFAULT false,

			updated_at timestamp NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
			num_updates integer NOT NULL DEFAULT 0
		);
	`)
	return err
}

func (store *Store) CreateTableSocialUsers(ctx context.Context) error {
	_, err := store.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS "`+store.SocialUsersTableName+`" (
			iss text NOT NULL,
			sub text NOT NULL,
			created_at timestamp NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
			"user" uuid NOT NULL REFERENCES "`+store.UsersTableName+`" ON DELETE CASCADE,

			profile text,
			picture text,
			website text,

			PRIMARY KEY (iss, sub)
		);
	`)
	return err
}

func (store *Store) CreateTableSessions(ctx context.Context) error {
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
