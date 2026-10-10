package oidcstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"sync"

	"github.com/in4it/go-devops-platform/auth/oidc"
	"github.com/in4it/go-devops-platform/storage"
)

const DEFAULT_PATH = "oidcstore.json"

var RetrieveTokenLock sync.Mutex

// GetOAuth2DataCopy returns a copy of all oauth2 entries. Use it instead of ranging
// over store.OAuth2Data directly, which races with concurrent writes.
func (store *Store) GetOAuth2DataCopy() map[string]oidc.OAuthData {
	store.Mu.Lock()
	defer store.Mu.Unlock()
	return maps.Clone(store.OAuth2Data)
}

// GetOAuth2DataByKey returns the oauth2 entry stored under key (the state).
func (store *Store) GetOAuth2DataByKey(key string) (oidc.OAuthData, bool) {
	store.Mu.Lock()
	defer store.Mu.Unlock()
	oauth2Data, ok := store.OAuth2Data[key]
	return oauth2Data, ok
}

func (store *Store) StoreEntry(state string, oauthData oidc.OAuthData) error {
	store.Mu.Lock()
	store.OAuth2Data[state] = oauthData
	store.Mu.Unlock()
	return nil
}

func (store *Store) setDiscoveryCache(key string, value oidc.DiscoveryCache) error {
	store.Mu.Lock()
	store.DiscoveryCache[key] = value
	store.Mu.Unlock()
	return nil
}

func (store *Store) setJwksCache(key string, value oidc.JwksCache) error {
	store.Mu.Lock()
	store.JwksCache[key] = value
	store.Mu.Unlock()
	return nil
}

func (store *Store) getDiscoveryCache(key string) (oidc.DiscoveryCache, bool) {
	discovery, ok := store.DiscoveryCache[key]
	return discovery, ok
}

func NewStore(storage storage.Iface) (*Store, error) {
	var store *Store

	filename := storage.ConfigPath(DEFAULT_PATH)

	// check if oidc.Store exists
	if !storage.FileExists(filename) {
		return getEmptyOIDCStore(storage)
	}

	data, err := storage.ReadFile(filename)
	if err != nil {
		return store, fmt.Errorf("config read error: %s", err)
	}
	decoder := json.NewDecoder(bytes.NewBuffer(data))
	err = decoder.Decode(&store)
	if err != nil {
		return store, fmt.Errorf("decode input error: %s", err)
	}
	if store.DiscoveryCache == nil {
		store.DiscoveryCache = make(map[string]oidc.DiscoveryCache)
	}
	if store.JwksCache == nil {
		store.JwksCache = make(map[string]oidc.JwksCache)
	}
	if store.OAuth2Data == nil {
		store.OAuth2Data = make(map[string]oidc.OAuthData)
	}

	store.storage = storage

	return store, nil
}

func getEmptyOIDCStore(storage storage.Iface) (*Store, error) {
	return &Store{
		OAuth2Data:     make(map[string]oidc.OAuthData),
		DiscoveryCache: make(map[string]oidc.DiscoveryCache),
		JwksCache:      make(map[string]oidc.JwksCache),
		storage:        storage,
	}, nil
}
