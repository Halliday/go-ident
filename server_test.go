package ident_test

import (
	"context"
	"os"
	"testing"

	"github.com/halliday/go-ident"
	"github.com/halliday/go-ident/pgxstore"
	"github.com/jackc/pgx/v4/pgxpool"
)

const issuer = "http://localhost/"
const defaultDatabaseUrl = "postgres://postgres:admin@localhost:5432/postgres?sslmode=disable"
const adminId = "9560a292-7893-4601-a195-8495cf7a63ae"
const jeffId = "3a5cfbc7-107d-4bb6-8b24-8ca69b57ea76"
const issFacebook = "https://www.facebook.com" // see https://www.facebook.com/.well-known/openid-configuration/

func TestServer(t *testing.T) {
	ctx := context.Background()

	server := createServer(t)

	subs, err := server.UserStore.RegisterUsers(ctx, "", false, []*ident.NewUser{
		{
			Userinfo: ident.Userinfo{
				Subject:           adminId,
				Email:             "admin@localhost",
				EmailVerified:     true,
				PreferredUsername: "Admin",
			},
			Password: ident.NewOption("admin132"),
		},
		{
			Userinfo: ident.Userinfo{
				Subject:       jeffId,
				Email:         "jeff.starkmann@gmail.com",
				EmailVerified: false, // not verified !
			},
			Password: ident.NewOption("jeff456"),
		},
	})
	if err != nil {
		t.Fatal("can not register users:", err)
	}
	if len(subs) != 2 || subs[0] != adminId || subs[1] != jeffId {
		t.Fatal("wrong number of subjects:", len(subs))
	}
	if subs[0] != adminId || subs[1] != jeffId {
		t.Fatal("unexpected subjects", adminId, jeffId)
	}

	//

	_, err = server.UserStore.RegisterUsers(ctx, "", false, []*ident.NewUser{
		{
			Userinfo: ident.Userinfo{
				Email: "jeff.starkmann@gmail.com",
			},
		},
	})
	if err == nil {
		t.Fatal("user was registered twice")
	}

	//

	subs, err = server.UserStore.RegisterUsers(ctx, issFacebook, false, []*ident.NewUser{
		{
			Userinfo: ident.Userinfo{
				Subject:       "fb-" + jeffId,
				Email:         "jeff.starkmann@gmail.com",
				EmailVerified: true,
			},
		},
		{
			Userinfo: ident.Userinfo{
				Subject:       "fb-df3eaf32-aacb-403a-9013-fb2ebf05d054",
				Email:         "grace.kelly@gmail.com",
				EmailVerified: true,
			},
		},
	})
	if err != nil {
		t.Fatal("can not register social users:", err)
	}
	if len(subs) != 2 {
		t.Fatal("wrong number of subjects in social registration:", len(subs))
	}
	if subs[0] != jeffId {
		t.Fatalf("social registration yields another id: %s != %s", subs[0], jeffId)
	}

	//

	refreshToken, accessToken, scopes, expiresIn, idToken, err := server.Login(ctx, ident.IdentAudience, nil, "jeff.starkmann@gmail.com", "jeff456")
	if err != nil {
		t.Fatal("can not login user:", err)
	}
	if refreshToken == "" || accessToken == "" || len(scopes) != 1 || expiresIn <= 0 || idToken == "" {
		t.Fatal("bad login response:", len(refreshToken), len(accessToken), scopes, len(idToken), expiresIn)
	}

	//

	if err := server.CompleteRegistration(ctx, jeffId, "jeff.starkmann@gmail.com"); err != nil {
		t.Fatal("can not complete registration:", err)
	}

	//

	// request updated session after registration completed
	accessToken, scopes, expiresIn, err = server.RefreshSession(ctx, refreshToken, nil)
	if err != nil {
		t.Fatal("can not refresh token:", err)
	}
	if accessToken == "" || len(scopes) != 2 || expiresIn <= 0 {
		t.Fatal("bad refresh response:", len(accessToken), scopes, len(idToken))
	}

	//

	userinfo, err := server.Userinfo(ctx, accessToken)
	if err != nil {
		t.Fatal("can not get userinfo:", err)
	}
	if userinfo.Subject != jeffId {
		t.Fatal("wrong userinfo subject:", userinfo.Subject)
	}

	//

	err = server.Revoke(ctx, refreshToken)
	if err != nil {
		t.Fatal("can not revoke token:", err)
	}

	//

	_, _, _, err = server.RefreshSession(ctx, refreshToken, nil)
	if err == nil {
		t.Fatal("the revoked token could still be refreshed")
	}
}

////////////////////////////////////////////////////////////////////////////////

func connectDatabase(t *testing.T) *pgxpool.Pool {
	ctx := context.Background()

	databaseUrl := os.Getenv("DATABASE_URL")
	if databaseUrl == "" {
		databaseUrl = defaultDatabaseUrl
	}

	pool, err := pgxpool.Connect(ctx, databaseUrl)
	if err != nil {
		t.Fatal(err)
	}

	return pool
}

func createStore(t *testing.T) *pgxstore.Store {
	ctx := context.Background()

	pool := connectDatabase(t)
	store := pgxstore.New(pool)

	store.UsersTableName = "test_users"
	store.SessionsTableName = "test_sessions"
	store.SocialUsersTableName = "test_social_users"

	_, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS "`+store.SessionsTableName+`";
		DROP TABLE IF EXISTS "`+store.SocialUsersTableName+`";
		DROP TABLE IF EXISTS "`+store.UsersTableName+`";`)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.SetupDatabase(ctx); err != nil {
		t.Fatal(err)
	}

	return store
}

type MyServer struct {
	*ident.Server
}

func createServer(t *testing.T) *MyServer {
	store := createStore(t)

	server := ident.NewServer(issuer, store, store, nil, nil)

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
