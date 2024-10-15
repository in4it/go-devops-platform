package scim

import (
	"github.com/in4it/go-devops-platform/storage"
	"github.com/in4it/go-devops-platform/users"
)

func New(storage storage.Iface, userStore *users.UserStore, token string, disableFunc DisableFunc, reactivateFunc ReactivateFunc) *scim {
	s := &scim{
		Token:          token,
		UserStore:      userStore,
		storage:        storage,
		DisableFunc:    disableFunc,
		ReactivateFunc: reactivateFunc,
	}
	return s
}
