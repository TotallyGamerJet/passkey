package main

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"

	"github.com/go-webauthn/webauthn/webauthn"
)

type InMem struct {
	// TODO: it would be nice to have a mutex here
	// TODO: use pointers to avoid copying
	users    map[string]*User
	sessions map[string]webauthn.SessionData
}

func (i *InMem) GenSessionID() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil

}

func NewInMem() *InMem {
	return &InMem{
		users:    make(map[string]*User),
		sessions: make(map[string]webauthn.SessionData),
	}
}

func (i *InMem) GetSession(token string) (webauthn.SessionData, bool) {
	slog.Debug("GetSession", "session", i.sessions[token])
	val, ok := i.sessions[token]

	return val, ok
}

func (i *InMem) SaveSession(token string, data webauthn.SessionData) {
	slog.Debug("SaveSession", "token", token, "data", data)
	i.sessions[token] = data
}

func (i *InMem) DeleteSession(token string) {
	slog.Debug("DeleteSession", "token", token)
	delete(i.sessions, token)
}

func (i *InMem) GetOrCreateUser(userName string) *User {
	slog.Debug("GetOrCreateUser", "user", userName)
	if _, ok := i.users[userName]; !ok {
		slog.Debug("creating new user", "user", userName)
		i.users[userName] = &User{
			ID:          []byte(userName),
			DisplayName: userName,
			Name:        userName,
		}
	}

	return i.users[userName]
}

func (i *InMem) SaveUser(user *User) {
	slog.Debug("SaveUser", "user", user.WebAuthnName())
	i.users[user.WebAuthnName()] = user
}
