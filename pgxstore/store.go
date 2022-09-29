package pgxstore

import (
	_ "embed"

	"github.com/halliday/go-ident"
	"github.com/halliday/go-module"
	"github.com/jackc/pgx/v4/pgxpool"
)

//go:embed messages.csv
var messages string

var _, e, Module = module.New("pgxstore", messages)

type Store struct {
	Pool                  *pgxpool.Pool
	MaxNumSessionsPerUser int
	UsersTableName        string
	SessionsTableName     string
	SocialUsersTableName  string
}

func New(pool *pgxpool.Pool) *Store {
	store := new(Store)
	store.SessionsTableName = "sessions"
	store.UsersTableName = "users"
	store.SocialUsersTableName = "social_users"
	store.Pool = pool
	store.MaxNumSessionsPerUser = 8
	return store
}

var _ = ident.SessionStore((*Store)(nil))
var _ = ident.UserStore((*Store)(nil))
