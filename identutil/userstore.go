package identutil

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/halliday/go-ident"
	"github.com/halliday/go-openid"
)

func NewMemUserStore() ident.UserStore {
	store := new(memUserStore)
	store.users = make(map[uuid.UUID]*memUser)
	return store
}

type memUser struct {
	*openid.Userinfo
	password *string
}

type memUserStore struct {
	users map[uuid.UUID]*memUser
}

func (store *memUserStore) FindUserPasswordReset(ctx context.Context, email string) (info *openid.Userinfo, err error) {
	return store.findUserByEmail(email), nil
}

func (store *memUserStore) RegisterUser(ctx context.Context, info *openid.Userinfo, password *string) (sub string, err error) {
	if user := store.findUserByEmail(info.Email); user != nil {
		if !user.EmailVerified {
			user.Email = info.Email
			return user.Subject, nil
		}
		return "", openid.ErrEmailAlreadyRegistered
	}

	user := CloneUserinfo(info)
	store.addUser(ctx, user, password)
	l.Info("user_created", "Id", user.Subject, "Username", user.PreferredUsername, "Email", user.Email, "Locale", user.Locale)
	return user.Subject, nil
}

// func (store *memUserStore) UpdateUserPassword(ctx context.Context, sub string, password string) error {
// 	user := store.users[uuid.MustParse(sub)]
// 	if user == nil {
// 		return openid.ErrNoUser
// 	}
// 	user.password = &password
// 	return nil
// }

// func (store *memUserStore) UpdateUserEmailVerified(ctx context.Context, sub string) error {
// 	user := store.users[uuid.MustParse(sub)]
// 	if user == nil {
// 		return openid.ErrNoUser
// 	}
// 	user.EmailVerified = true
// 	return nil
// }

func (store *memUserStore) findUserByEmail(email string) *openid.Userinfo {
	if email == "" {
		return nil
	}
	for _, user := range store.users {
		if strings.EqualFold(user.Email, email) {
			return user.Userinfo
		}
	}
	return nil
}

func (store *memUserStore) findUserBySocial(social string, sub string) *openid.Userinfo {
	for _, user := range store.users {
		if user.SocialProviders != nil && user.SocialProviders[social] == sub {
			return user.Userinfo
		}
	}
	return nil
}

func (store *memUserStore) addUser(ctx context.Context, info *openid.Userinfo, password *string) {
	id := uuid.New()
	info.Subject = id.String()
	store.users[id] = &memUser{info, password}
}

func (store *memUserStore) LoginUser(ctx context.Context, email string, password string, scopes ident.Scopes) (info *openid.Userinfo, grantedScopes ident.Scopes, err error) {
	for _, user := range store.users {
		if user.Email == email {
			if user.password != nil && *user.password == password {
				if scopes.Has("openid") {
					grantedScopes = openid.Scopes{"openid"}
				}
				return user.Userinfo, grantedScopes, nil
			}
			return nil, nil, nil
		}
	}
	return nil, nil, nil
}

func (store *memUserStore) RegisterSocialUser(ctx context.Context, social string, info *openid.Userinfo) (sub string, err error) {
	if user := store.findUserBySocial(social, info.Subject); user != nil {
		return user.Subject, nil
	}

	if info.Email != "" {
		if user := store.findUserByEmail(info.Email); user != nil {
			if info.EmailVerified {
				// TODO maybe update some userinfo fields
				user.EmailVerified = true
			}
			return user.Subject, nil
		}
	}

	user := CloneUserinfo(info)
	info.SocialProviders = map[string]string{
		social: user.Subject,
	}
	store.addUser(ctx, user, nil)
	l.Info("social_user_created", "Social", social, "Id", user.Subject, "Username", user.PreferredUsername, "Email", user.Email, "Locale", user.Locale)
	return user.Subject, err
}

func (store *memUserStore) Userinfo(ctx context.Context, sub string) (*openid.Userinfo, error) {
	user := store.users[uuid.MustParse(sub)]
	if user == nil {
		return nil, nil
	}
	return user.Userinfo, nil
}

func (store *memUserStore) UpdateUser(ctx context.Context, update *ident.UserUpdate) error {
	id := uuid.MustParse(update.Subject)
	original := store.users[id]
	if original == nil {
		return openid.ErrNoUser
	}
	info := CloneUserinfo(&update.Userinfo)
	info.UpdatedAt = time.Now().Unix()
	info.CreatedAt = original.CreatedAt
	store.users[id].Userinfo = info
	l.Info("user_updated", "Id", original.Subject, "Username", original.PreferredUsername, "Email", original.Email, "Locale", original.Locale)
	return nil
}

func (store *memUserStore) DeleteUsers(ctx context.Context, ids []string) (numDeleted int, err error) {
	for _, id := range ids {
		if _, ok := store.users[uuid.MustParse(id)]; ok {
			delete(store.users, uuid.MustParse(id))
			numDeleted++
		}
	}
	return numDeleted, nil
}

func CloneUserinfo(info *openid.Userinfo) *openid.Userinfo {
	clone := new(openid.Userinfo)
	*clone = *info
	return clone
}
