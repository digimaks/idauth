// SPDX-License-Identifier: EUPL-1.2

//nolint:tagliatelle
package authorizationcode

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"sync"

	"azugo.io/core/cache"
	"azugo.io/core/http"
	"github.com/lx-lib/lx-idauth/core"
	"github.com/oklog/ulid/v2"
)

type PARItem struct {
	ClientID string `json:"client_id"`
	RawQuery string `json:"raw_query"`
}

// RefreshTokenItem is what a rotating refresh token is bound to. Session
// is a template — redemption clears its ID/LastAccessed and mints a fresh
// one, exactly like AuthCodeItem does for the authorization_code grant.
type RefreshTokenItem struct {
	ClientID string       `json:"client_id"`
	Scope    string       `json:"scope"`
	JKT      string       `json:"jkt"`
	Session  core.Session `json:"session"`
}

type AuthCodeItem struct {
	Code                string `json:"code"`
	ClientID            string `json:"client_id"`
	UserID              string `json:"user_id"`
	RedirectURI         string `json:"redirect_uri"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Scope               string `json:"scope"`
	IssuerState         string `json:"issuer_state,omitempty"`
	// NoTXCode marks a pre-auth code issued without a transaction code
	// (test/dev offers) — HandlePreAuthorized skips tx_code validation for it.
	NoTXCode bool         `json:"no_tx_code,omitempty"`
	Session  core.Session `json:"session"`
}

type StateItem struct {
	State        string `json:"state"`
	ResponseType string `json:"response_type"`
	Scope        string `json:"scope"`
	IssuerState  string `json:"issuer_state,omitempty"`
}

type AuthCodeItems struct {
	CacheItems []AuthCodeItem `json:"authCodeItems"`
}

const (
	authCodeCache         = "auth_code"
	stateCache            = "auth_code_state"
	preAuthCache          = "pre_auth_code"
	parCacheName          = "par_request"
	refreshTokenCacheName = "refresh_token"
)

type Store struct {
	authCodeCache     cache.Instance[AuthCodeItem]
	stateCache        cache.Instance[StateItem]
	preAuthCache      cache.Instance[int]
	parCache          cache.Instance[PARItem]
	refreshTokenCache cache.Instance[RefreshTokenItem]
	scopes            scopeSet
	mu                sync.Mutex
}

type CacheProvider interface {
	Cache() *cache.Cache
}

func NewAuthCodeStore(app CacheProvider, config *Configuration) (*Store, error) {
	sid := &Store{
		scopes: newScopeSet(config.Scopes),
	}

	var err error

	sid.authCodeCache, err = cache.Create[AuthCodeItem](app.Cache(), authCodeCache, cache.DefaultTTL(config.AuthCodeTTL))
	if err != nil {
		return nil, err
	}

	sid.stateCache, err = cache.Create[StateItem](app.Cache(), stateCache, cache.DefaultTTL(config.StateTTL))
	if err != nil {
		return nil, err
	}

	sid.preAuthCache, err = cache.Create[int](app.Cache(), preAuthCache, cache.DefaultTTL(config.PreAuthTTL))
	if err != nil {
		return nil, err
	}

	sid.parCache, err = cache.Create[PARItem](app.Cache(), parCacheName, cache.DefaultTTL(config.PARTTL))
	if err != nil {
		return nil, err
	}

	sid.refreshTokenCache, err = cache.Create[RefreshTokenItem](app.Cache(), refreshTokenCacheName, cache.DefaultTTL(config.RefreshTokenTTL))
	if err != nil {
		return nil, err
	}

	return sid, nil
}

// IsScopeSupported reports whether every scope token in the space-separated
// scope string is in the configured allowlist.
func (st *Store) IsScopeSupported(scope string) bool {
	return st.scopes.Supported(scope)
}

func (st *Store) SetItem(ctx context.Context, item AuthCodeItem) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	if err := st.authCodeCache.Set(ctx, item.Code, item); err != nil {
		return err
	}

	return nil
}

func (st *Store) GetItem(ctx context.Context, code string, codeVerifier string) (*AuthCodeItem, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	value, err := st.authCodeCache.Get(ctx, code)
	if err != nil {
		return nil, err
	}

	// verify code challenge
	if value.CodeChallengeMethod == "S256" {
		codeVerifier = GenerateCodeChallenge(codeVerifier)
	}

	if value.CodeChallenge != codeVerifier {
		return nil, http.NotFoundError{Resource: "code_verifier"}
	}

	return &value, nil
}

func (st *Store) DeleteItem(ctx context.Context, code string) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	if err := st.authCodeCache.Delete(ctx, code); err != nil {
		return err
	}

	return nil
}

func (st *Store) SetState(ctx context.Context, item StateItem) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	if err := st.stateCache.Set(ctx, item.State, item); err != nil {
		return err
	}

	return nil
}

func (st *Store) PopState(ctx context.Context, state string) (*StateItem, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	stateItem, err := st.stateCache.Pop(ctx, state)
	if err != nil {
		return nil, err
	}

	return &stateItem, nil
}

// SetTXCode stores a numeric tx_code associated with a pre-auth code.
func (st *Store) SetTXCode(ctx context.Context, preAuthCode string, txCode int) error {
	return st.preAuthCache.Set(ctx, preAuthCode, txCode)
}

// ValidateTXCode checks the provided string matches the stored tx_code.
func (st *Store) ValidateTXCode(ctx context.Context, preAuthCode string, txCode string) bool {
	stored, err := st.preAuthCache.Get(ctx, preAuthCode)
	if err != nil {
		return false
	}

	return strconv.Itoa(stored) == txCode
}

// DeleteTXCode removes the tx_code entry (enforces single-use, spec §4.1.1).
func (st *Store) DeleteTXCode(ctx context.Context, preAuthCode string) error {
	return st.preAuthCache.Delete(ctx, preAuthCode)
}

// GetPreAuthItem retrieves a pre-auth AuthCodeItem without PKCE verification.
func (st *Store) GetPreAuthItem(ctx context.Context, preAuthCode string) (*AuthCodeItem, error) {
	item, err := st.authCodeCache.Get(ctx, preAuthCode)
	if err != nil {
		return nil, err
	}

	if item.Code == "" {
		return nil, cache.KeyNotFoundError{Key: preAuthCode}
	}

	return &item, nil
}

// SetPAR stores a validated pushed authorization request and returns its
// single-use identifier (without the urn:... prefix).
func (st *Store) SetPAR(ctx context.Context, item PARItem) (string, error) {
	id := ulid.Make().String()

	if err := st.parCache.Set(ctx, id, item); err != nil {
		return "", err
	}

	return id, nil
}

// PopPAR retrieves and deletes a pushed authorization request by its
// identifier. A second call for the same id returns an error.
func (st *Store) PopPAR(ctx context.Context, id string) (*PARItem, error) {
	item, err := st.parCache.Pop(ctx, id)
	if err != nil {
		return nil, err
	}

	return &item, nil
}

// IssueRefreshToken generates a fresh opaque refresh token, stores item
// keyed by the token's SHA-256 hash (never the raw value), and returns the
// raw token — the only time it exists outside this call and the client.
func (st *Store) IssueRefreshToken(ctx context.Context, item RefreshTokenItem) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	token := base64.RawURLEncoding.EncodeToString(buf)

	if err := st.refreshTokenCache.Set(ctx, hashRefreshToken(token), item); err != nil {
		return "", err
	}

	return token, nil
}

// RedeemRefreshToken retrieves and deletes the item bound to token. A
// second call with the same token returns an error (single-use/rotation).
func (st *Store) RedeemRefreshToken(ctx context.Context, token string) (*RefreshTokenItem, error) {
	item, err := st.refreshTokenCache.Pop(ctx, hashRefreshToken(token))
	if err != nil {
		return nil, err
	}

	return &item, nil
}

func hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}
