package scim

import (
	"encoding/json"
	"fmt"

	"github.com/in4it/go-devops-platform/users"
)

// listUserResponse returns a SCIM ListResponse. start is the 1-based startIndex (RFC 7644 section 3.4.2.4),
// values < 1 are interpreted as 1. count is the maximum number of resources to return, -1 (or any negative value)
// means no limit; callers must map a negative count from the request to 0.
func listUserResponse(users []users.User, attributes string, count, start int) ([]byte, error) {
	totalResults := len(users)
	if start < 1 {
		start = 1
	}
	if start > len(users) {
		users = users[:0]
	} else {
		users = users[start-1:]
	}
	if count >= 0 && len(users) > count {
		users = users[0:count]
	}
	response := UserResponse{
		TotalResults: totalResults,
		ItemsPerPage: len(users),
		StartIndex:   start,
		Schemas:      getSchemas("ListResponse"),
		Resources:    make([]UserResource, len(users)),
	}
	for k := range users {
		response.Resources[k] = UserResource{
			ID:       users[k].ID,
			UserName: users[k].Login,
		}
	}
	out, err := json.Marshal(response)
	if err != nil {
		return out, fmt.Errorf("json marshal error: %s", err)
	}
	return out, nil
}

func userResponse(user users.User) ([]byte, error) {
	response := PostUserRequest{
		Schemas:  getSchemas("User"),
		Id:       user.ID,
		UserName: user.Login,
		Active:   !user.Suspended,
	}
	out, err := json.Marshal(response)
	if err != nil {
		return out, fmt.Errorf("json marshal error: %s", err)
	}
	return out, nil
}

func getSchemas(responseType string) []string {
	if responseType == "User" {
		return []string{"urn:ietf:params:scim:schemas:core:2.0:User"}
	}
	return []string{"urn:ietf:params:scim:api:messages:2.0:" + responseType}

}
