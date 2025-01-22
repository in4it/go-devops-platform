package users

import (
	"time"

	"github.com/in4it/go-devops-platform/storage"
)

type UserStore struct {
	Users     []User `json:"users"`
	autoSave  bool
	maxUsers  int
	storage   storage.Iface
	UserHooks UserHooks
}

type User struct {
	ID                               string      `json:"id"`
	Login                            string      `json:"login"`
	Role                             string      `json:"role"`
	OIDCID                           string      `json:"oidcID,omitempty"`
	SAMLID                           string      `json:"samlID,omitempty"`
	Provisioned                      bool        `json:"provisioned,omitempty"`
	Password                         string      `json:"password,omitempty"`
	Suspended                        bool        `json:"suspended"`
	ConnectionsDisabledOnAuthFailure bool        `json:"connectionsDisabledOnAuthFailure"`
	Factors                          []Factor    `json:"factors"`
	ExternalID                       string      `json:"externalID,omitempty"`
	LastLogin                        TimeOrEmpty `json:"lastLogin"`
}

type TimeOrEmpty time.Time

func (t *TimeOrEmpty) UnmarshalJSON(data []byte) error {
	if string(data) == `""` {
		*t = TimeOrEmpty(time.Time{})
		return nil
	}
	tt := time.Time(*t)
	err := tt.UnmarshalJSON(data)
	if err != nil {
		return err
	}
	*t = TimeOrEmpty(tt)
	return nil
}
func (t TimeOrEmpty) MarshalJSON() ([]byte, error) {
	return time.Time(t).MarshalJSON()
}
func (t TimeOrEmpty) String() string {
	return time.Time(t).String()
}
func (t TimeOrEmpty) IsZero() bool {
	return time.Time(t).IsZero()
}
func (t TimeOrEmpty) UTC() time.Time {
	return time.Time(t).UTC()
}

type Factor struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Secret string `json:"secret"`
}

type DisableFunc func(storage.Iface, User) error
type ReactivateFunc func(storage.Iface, User) error
type DeleteFunc func(storage.Iface, User) error

type UserHooks struct {
	DisableFunc    DisableFunc
	ReactivateFunc ReactivateFunc
	DeleteFunc     DeleteFunc
}
