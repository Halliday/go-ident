package pgxstore

import (
	"context"
	"os"
	"testing"

	"github.com/halliday/go-ident"
	"github.com/jackc/pgx/v4/pgxpool"
)

const defaultDatabaseUrl = "postgres://postgres:admin@localhost:5432/postgres?sslmode=disable"

const adminId = "9560a292-7893-4601-a195-8495cf7a63ae"

func TestStore(t *testing.T) {
	ctx := context.Background()

	store := createStore(t)

	subs, err := store.RegisterUsers(ctx, "", false, []*ident.NewUser{
		{
			Userinfo: ident.Userinfo{
				Subject:           adminId,
				Email:             "admin@localhost",
				PreferredUsername: "Admin",
			},
			Password: ident.NewOption("admin"),
		},
		{
			Userinfo: ident.Userinfo{
				Subject:           "3a5cfbc7-107d-4bb6-8b24-8ca69b57ea76",
				Email:             "jeff.starkmann@gmail.com",
				PreferredUsername: "Jeff Starlmann",
			},
		},
	})
	if err != nil {
		t.Fatal("can not register user:", err)
	}

	if subs[0] != adminId {
		t.Fatalf("wrong subject: %s != %s", subs[0], adminId)
	}

	//

	sub, err := store.LoginUser(ctx, "admin@localhost", "admin")
	if err != nil {
		t.Fatal("can not login user:", err)
	}

	if sub != adminId {
		t.Fatal("wrong login subject:", sub)
	}

	//

	users, _, err := store.FindUsers(ctx, ident.Selection{}, "", 0)
	if err != nil {
		t.Fatal("can not find users:", err)
	}

	if len(users) != 2 {
		t.Fatal("no user found")
	}

	if users[0].Subject != adminId || users[0].Email != "admin@localhost" || users[0].PreferredUsername != "Admin" {
		t.Fatal("wrong user info:", users[0])
	}

	//

	numUpdated, err := store.UpdateUsers(ctx, ident.Selection{Ids: []string{adminId}}, &ident.UserUpdate{
		PreferredUsername: ident.NewOption("Admin2"),
		Suspended:         ident.NewOption(true),
	})
	if err != nil {
		t.Fatal("can not update user:", err)
	}
	if numUpdated != 1 {
		t.Fatal("wrong number of updated users:", numUpdated)
	}

	//

	users, _, err = store.FindUsers(ctx, ident.Selection{Ids: []string{adminId}}, "", 1)
	if err != nil {
		t.Fatal("can not find users: (2)", err)
	}

	if len(users) != 1 {
		t.Fatal("no user found (2)")
	}

	if users[0].Subject != adminId || users[0].PreferredUsername != "Admin2" {
		t.Fatal("wrong user info (2):", users[0])
	}
}

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

func createStore(t *testing.T) *Store {
	ctx := context.Background()

	pool := connectDatabase(t)
	store := New(pool)

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
