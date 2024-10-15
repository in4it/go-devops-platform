package scim

import (
	"github.com/in4it/go-devops-platform/storage"
	"github.com/in4it/go-devops-platform/users"
)

func New(storage storage.Iface, userStore *users.UserStore, token string) *scim {
	s := &scim{
		Token:     token,
		UserStore: userStore,
		storage:   storage,
	}
	return s
}
