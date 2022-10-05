package pgxstore

import (
	"context"
	"testing"

	"github.com/halliday/go-ident"
)

func TestSessions(t *testing.T) {
	ctx := context.Background()

	store := createStore(t)

	subs, err := store.RegisterUsers(ctx, "", false, []*ident.NewUser{
		{
			Userinfo: ident.Userinfo{
				Email:             "tabi@localhost",
				PreferredUsername: "Tabi",
			},
			Password: ident.NewOption("baum"),
		},
	})
	if err != nil {
		t.Fatal("can not register user:", err)
	}

	sess, err := store.CreateSession(ctx, "test", subs[0], []string{"a", "b"})
	if err != nil {
		t.Fatal("can not create session:", err)
	}

	numUpdated, err := store.UpdateSessions(ctx, sess, "", []string{"c"}, []string{"a"})
	if err != nil {
		t.Fatal("can not update session:", err)
	}
	if numUpdated != 1 {
		t.Fatal("wrong number of updated sessions:", numUpdated)
	}

	sub, grantedScopes, err := store.RefreshSession(ctx, sess, nil)
	if err != nil {
		t.Fatal("can not refresh session:", err)
	}
	if sub != subs[0] {
		t.Fatal("wrong subject:", sub)
	}
	if len(grantedScopes) != 2 && ((grantedScopes[0] != "a" && grantedScopes[1] != "c") || (grantedScopes[0] != "c" && grantedScopes[1] != "a")) {
		t.Fatal("wrong number of granted scopes:", len(grantedScopes))
	}
}
