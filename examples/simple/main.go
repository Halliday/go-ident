package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/halliday/go-ident"
	"github.com/halliday/go-ident/pgxstore"
	"github.com/halliday/go-openid"
	"github.com/jackc/pgx/v4/pgxpool"
)

const issuer = "http://localhost:8080/"
const defaultDatabaseUrl = "postgres://postgres:admin@localhost:5432/postgres?sslmode=disable"
const adminId = "9560a292-7893-4601-a195-8495cf7a63ae"
const adminDefaultPassword = "admin"
const addr = ":8080"

func main() {
	ctx := context.Background()

	server := createServer()

	_, err := server.UserStore.RegisterUsers(ctx, "", true, []*ident.NewUser{
		{
			Userinfo: ident.Userinfo{
				Subject:           adminId,
				PreferredUsername: "Admin",
				Email:             "admin@localhost",
				EmailVerified:     true,
			},
			Password: ident.NewOption(adminDefaultPassword),
		},
	})
	if err != nil {
		log.Fatalf("can not register admin users: %v", err)
	}

	log.Printf("server listening on %s", addr)
	http.ListenAndServe(addr, middlewareDisableCors(server))
}

func middlewareDisableCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		next.ServeHTTP(w, r)
	})
}

////////////////////////////////////////////////////////////////////////////////

func connectDatabase() *pgxpool.Pool {
	ctx := context.Background()

	databaseUrl := os.Getenv("DATABASE_URL")
	if databaseUrl == "" {
		databaseUrl = defaultDatabaseUrl
	}

	pool, err := pgxpool.Connect(ctx, databaseUrl)
	if err != nil {
		panic(fmt.Errorf("can not connect to database: %w", err))
	}

	return pool
}

var www = http.FileServer(http.Dir("www"))

//

type MyServer struct {
	*ident.Server
}

func createServer() *MyServer {
	store := createStore()

	myStore := &MyStore{store}

	socials := []*ident.SocialProvider{
		{
			ClientId:     "solution-lab-1",
			ClientSecret: "123456",
			Config:       openid.MustDiscover("https://login.waziup.io/auth/realms/waziup"),
		},
	}

	server := ident.NewServer(issuer, myStore, myStore, socials, www)

	server.Config.AuthorizationEndpoint = "http://localhost:3000/"

	server.SendMail = PrintEmailToLog

	myServer := &MyServer{server}

	server.GrantScopes = myServer.GrantScopes

	return myServer
}

func (s *MyServer) GrantScopes(ctx context.Context, aud string, sub string, scopes []string) (grantedScopes []string, err error) {
	info, err := s.UserStore.Userinfo(ctx, sub)
	if err != nil {
		return nil, err
	}
	if info.Subject == adminId {
		return []string{"admin", "openid"}, nil
	}
	if info.EmailVerified {
		return []string{"member", "openid"}, nil
	}
	return []string{"openid"}, nil
}

//

type MyStore struct {
	*pgxstore.Store
}

func createStore() *pgxstore.Store {
	ctx := context.Background()

	pool := connectDatabase()
	store := pgxstore.New(pool)

	store.UsersTableName = "simple_users"
	store.SessionsTableName = "simple_sessions"
	store.SocialUsersTableName = "simple_social_users"

	if err := store.SetupDatabase(ctx); err != nil {
		log.Fatalf("can not setup database: %v", err)
	}

	return store
}

func (s *MyStore) UpdateUsers(ctx context.Context, sel ident.Selection, u *ident.UserUpdate) (numUpdated int, err error) {
	numUpdated, err = s.Store.UpdateUsers(ctx, sel, u)
	if err != nil {
		return 0, err
	}

	if len(sel.Ids) == 1 {
		if u.EmailVerified.Valid && u.EmailVerified.Value {
			_, err = s.UpdateSessions(ctx, "", sel.Ids[0], []string{"member"}, nil)
			if err != nil {
				return 0, err
			}
		}
	}

	return numUpdated, err
}
