package scim

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	memorystorage "github.com/in4it/go-devops-platform/storage/memory"
	"github.com/in4it/go-devops-platform/users"
)

func newScimWithUsers(t *testing.T, userCount int) (*Scim, []users.User) {
	t.Helper()
	storage := &memorystorage.MockMemoryStorage{}
	userStore, err := users.NewUserStore(storage, USERSTORE_MAX_USERS)
	if err != nil {
		t.Fatalf("cannot create new user store: %s", err)
	}
	usersToCreate := make([]users.User, userCount)
	for i := 0; i < userCount; i++ {
		usersToCreate[i] = users.User{Login: fmt.Sprintf("user-%d@domain.inv", i)}
	}
	created, err := userStore.AddUsers(usersToCreate)
	if err != nil {
		t.Fatalf("cannot create users: %s", err)
	}
	return New(storage, userStore, "token"), created
}

func getUsersPage(t *testing.T, s *Scim, query string) UserResponse {
	t.Helper()
	req := httptest.NewRequest("GET", "http://example.com/api/scim/v2/Users?"+query, nil)
	w := httptest.NewRecorder()
	s.GetUsersHandler(w, req)
	resp := w.Result()
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}
	var userResponse UserResponse
	if err := json.NewDecoder(resp.Body).Decode(&userResponse); err != nil {
		t.Fatalf("Could not decode output: %s", err)
	}
	return userResponse
}

func TestUsersGetPagingNoSkippedUsers(t *testing.T) {
	totalUserCount := 25
	s, created := newScimWithUsers(t, totalUserCount)
	seen := []string{}
	for start := 1; start <= totalUserCount; start += 10 {
		page := getUsersPage(t, s, fmt.Sprintf("count=10&startIndex=%d", start))
		if page.TotalResults != totalUserCount {
			t.Fatalf("wrong totalResults: %d", page.TotalResults)
		}
		if page.StartIndex != start {
			t.Fatalf("wrong startIndex: %d", page.StartIndex)
		}
		for _, resource := range page.Resources {
			seen = append(seen, resource.UserName)
		}
	}
	if len(seen) != totalUserCount {
		t.Fatalf("expected %d users over all pages, got %d", totalUserCount, len(seen))
	}
	for k := range created {
		if seen[k] != created[k].Login {
			t.Fatalf("user %d mismatch: %s (actual) vs %s (expected)", k, seen[k], created[k].Login)
		}
	}
}

func TestUsersGetPagingInvalidValues(t *testing.T) {
	s, created := newScimWithUsers(t, 5)
	tests := []struct {
		query         string
		expectedCount int
		expectedStart int
		firstLogin    string
	}{
		{query: "count=-5&startIndex=1", expectedCount: 0, expectedStart: 1},
		{query: "count=-1&startIndex=1", expectedCount: 0, expectedStart: 1},
		{query: "count=2&startIndex=0", expectedCount: 2, expectedStart: 1, firstLogin: created[0].Login},
		{query: "count=2&startIndex=-10", expectedCount: 2, expectedStart: 1, firstLogin: created[0].Login},
		{query: "count=10&startIndex=6", expectedCount: 0, expectedStart: 6},
		{query: "count=10&startIndex=5", expectedCount: 1, expectedStart: 5, firstLogin: created[4].Login},
		{query: "", expectedCount: 5, expectedStart: 1, firstLogin: created[0].Login},
	}
	for _, test := range tests {
		page := getUsersPage(t, s, test.query)
		if len(page.Resources) != test.expectedCount || page.ItemsPerPage != test.expectedCount {
			t.Fatalf("%s: expected %d resources, got %d (itemsPerPage %d)", test.query, test.expectedCount, len(page.Resources), page.ItemsPerPage)
		}
		if page.StartIndex != test.expectedStart {
			t.Fatalf("%s: expected startIndex %d, got %d", test.query, test.expectedStart, page.StartIndex)
		}
		if page.TotalResults != 5 {
			t.Fatalf("%s: expected totalResults 5, got %d", test.query, page.TotalResults)
		}
		if test.firstLogin != "" && page.Resources[0].UserName != test.firstLogin {
			t.Fatalf("%s: wrong first login: %s", test.query, page.Resources[0].UserName)
		}
	}
}
