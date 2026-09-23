// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"errors"
	"net/url"
	"time"

	"github.com/digimaks/idauth/authorizationcode"
	"github.com/digimaks/idauth/dpop"
	"github.com/digimaks/idauth/routes/request"
	"github.com/digimaks/idauth/routes/response"
	"github.com/digimaks/idauth/svcerrors"

	"azugo.io/azugo"
	"azugo.io/core/http"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lx-lib/lx-idauth/core"
	"github.com/oklog/ulid/v2"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

const (
	GrantTypeAuthorizationCode     = "authorization_code"
	GrantTypeClientCredentials     = "client_credentials"
	GrantTypeRefreshToken          = "refresh_token"
	ClientAssertationTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec
	GrantTypePreAuthorizedCode     = "urn:ietf:params:oauth:grant-type:pre-authorized_code"   //nolint:gosec

)

//nolint:errname
var unsupportedGrantType = &response.TokenResponseError{
	Type:        "unsupported_grant_type",
	Description: "Unsupported grant type",
}

//nolint:errname
var invalidClient = &response.TokenResponseError{
	Type:        "invalid_client",
	Description: "Invalid client: Possible causes may be missing / invalid client_id, missing client authentication, invalid or expired client secret, invalid or expired JWT authentication, invalid or expired client X.509 certificate, or an unexpected client authentication method",
}

//nolint:errname
var invalidDPoPProof = &response.TokenResponseError{
	Type:        "invalid_dpop_proof",
	Description: "Invalid DPoP proof: missing, malformed, expired, replayed, or bound to a different request",
}

func (r *router) token(ctx *azugo.Context) {
	ctx.Header.Set("Cache-Control", "no-store")

	jkt, ok := r.dpopJKT(ctx)
	if !ok {
		return
	}

	grantType := ctx.Form.StringOptional("grant_type")

	switch {
	case grantType != nil && *grantType == GrantTypeAuthorizationCode:
		authorizationcode.HandleAuthorization(ctx, r.IDAuth(), r.AuthCodeStore(), r.Config().SessionTimeout, r.Audit(), jkt, r.attest)
	case grantType != nil && *grantType == GrantTypeRefreshToken:
		authorizationcode.HandleRefreshToken(ctx, r.IDAuth(), r.AuthCodeStore(), r.Config().SessionTimeout, jkt)
	case grantType != nil && *grantType == GrantTypePreAuthorizedCode:
		authorizationcode.HandlePreAuthorized(ctx, r.IDAuth(), r.AuthCodeStore(),
			r.Config().SessionTimeout, jkt, r.attest, r.Config().RequireClientAttestationPreauth)
	default:
		r.handleClientCredentials(ctx, jkt)
	}
}

func (r *router) dpopJKT(ctx *azugo.Context) (string, bool) {
	proof := ctx.Header.Get(dpop.HeaderName)
	if proof == "" {
		return "", true
	}

	jkt, err := r.dpop.Validate(ctx, proof, fasthttp.MethodPost, "")
	if err != nil {
		svcerrors.SetHeader(ctx, svcerrors.TokenDPoPProofInvalid)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(invalidDPoPProof)

		return "", false
	}

	return jkt, true
}

func (r *router) handleClientCredentials(ctx *azugo.Context, jkt string) {
	req := &request.TokenRequest{}

	if err := ctx.Body.JSON(req); err != nil {
		ctx.Log().Error("failed to decode token request body", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:token:invalidRequestBody"))

		return
	}

	if req.ClientAssertionType != ClientAssertationTypeJWTBearer {
		svcerrors.SetHeader(ctx, svcerrors.ClientCredentialsUnsupportedAssertionType)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(unsupportedGrantType)

		return
	}

	aud, err := url.JoinPath(ctx.BaseURL(), ctx.RouterPath())
	if err != nil {
		ctx.Log().Error("failed to build token endpoint audience URL", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:token:audienceBuildFailed"))

		return
	}

	var claims jwt.RegisteredClaims

	token, err := jwt.ParseWithClaims(
		req.ClientAssertion, &claims, func(token *jwt.Token) (any, error) {
			sub, err := token.Claims.GetSubject()
			if err != nil {
				return nil, invalidClient
			}

			if sub == "" || (req.ClientID != "" && sub != req.ClientID) {
				return nil, invalidClient
			}

			client, err := r.IDAuth().Clients().GetClient(sub)
			if err != nil {
				if errors.Is(err, http.NotFoundError{Resource: "client"}) {
					return nil, invalidClient
				}

				return nil, err
			}

			// Check if the client has any certificates or secrets
			if len(client.Certificates) == 0 && len(client.Secrets) == 0 {
				return nil, invalidClient
			}

			// Check if the client can request specific scope
			var valid bool

			for _, scope := range client.Scopes {
				if req.Scope == scope {
					valid = true

					break
				}
			}

			if !valid {
				return nil, invalidClient
			}

			keys := jwt.VerificationKeySet{
				Keys: make([]jwt.VerificationKey, 0, len(client.Certificates)+len(client.Secrets)),
			}

			for _, cert := range client.Certificates {
				switch token.Method.Alg() {
				case jwt.SigningMethodES256.Name, jwt.SigningMethodES384.Name, jwt.SigningMethodES512.Name:
					key, err := jwt.ParseECPublicKeyFromPEM([]byte(cert))
					if err == nil {
						keys.Keys = append(keys.Keys, key)
					}
				case "EdDSA":
					key, err := jwt.ParseEdPublicKeyFromPEM([]byte(cert))
					if err == nil {
						keys.Keys = append(keys.Keys, key)
					}
				case jwt.SigningMethodRS256.Name, jwt.SigningMethodRS384.Name, jwt.SigningMethodRS512.Name:
					key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
					if err == nil {
						keys.Keys = append(keys.Keys, key)
					}
				default:
					return nil, invalidClient
				}
			}

			for _, secret := range client.Secrets {
				keys.Keys = append(keys.Keys, []byte(secret))
			}

			if len(keys.Keys) == 0 {
				return nil, invalidClient
			}

			return keys, nil
		}, jwt.WithAudience(aud),
		jwt.WithLeeway(30*time.Second),
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{
			jwt.SigningMethodES256.Name,
			jwt.SigningMethodES384.Name,
			jwt.SigningMethodES512.Name,
			"EdDSA",
			jwt.SigningMethodRS256.Name,
			jwt.SigningMethodRS384.Name,
			jwt.SigningMethodRS512.Name,
		}),
	)
	if err != nil {
		var resp *response.TokenResponseError
		if errors.As(err, &resp) {
			svcerrors.SetHeader(ctx, svcerrors.ClientCredentialsAssertionInvalid)
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.JSON(resp)

			return
		}

		if errors.Is(err, jwt.ErrInvalidKey) ||
			errors.Is(err, jwt.ErrInvalidKeyType) ||
			errors.Is(err, jwt.ErrHashUnavailable) ||
			errors.Is(err, jwt.ErrTokenMalformed) ||
			errors.Is(err, jwt.ErrTokenUnverifiable) ||
			errors.Is(err, jwt.ErrTokenSignatureInvalid) ||
			errors.Is(err, jwt.ErrTokenRequiredClaimMissing) ||
			errors.Is(err, jwt.ErrTokenInvalidAudience) ||
			errors.Is(err, jwt.ErrTokenExpired) ||
			errors.Is(err, jwt.ErrTokenUsedBeforeIssued) ||
			errors.Is(err, jwt.ErrTokenInvalidIssuer) ||
			errors.Is(err, jwt.ErrTokenInvalidSubject) ||
			errors.Is(err, jwt.ErrTokenNotValidYet) ||
			errors.Is(err, jwt.ErrTokenInvalidId) ||
			errors.Is(err, jwt.ErrTokenInvalidClaims) ||
			errors.Is(err, jwt.ErrInvalidType) {
			svcerrors.SetHeader(ctx, svcerrors.ClientCredentialsAssertionInvalid)
			ctx.StatusCode(fasthttp.StatusBadRequest)
			ctx.JSON(invalidClient)

			return
		}

		ctx.Log().Error("unexpected error parsing client assertion JWT", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:token:assertionParseFailed"))

		return
	}

	if !token.Valid {
		svcerrors.SetHeader(ctx, svcerrors.ClientCredentialsAssertionInvalid)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(invalidClient)

		return
	}

	if exp, err := token.Claims.GetExpirationTime(); err != nil && time.Until(exp.Time) > 5*time.Minute {
		svcerrors.SetHeader(ctx, svcerrors.ClientCredentialsAssertionInvalid)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(invalidClient)

		return
	}

	if claims.ID == "" {
		svcerrors.SetHeader(ctx, svcerrors.ClientCredentialsAssertionInvalid)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(invalidClient)

		return
	}

	exists, err := r.jti.Get(ctx, claims.ID)
	if err != nil {
		ctx.Log().Error("failed to check JTI, skipping JTI check", zap.Error(err))
		// Continue without checking JTI
		exists = false
	}

	if exists {
		svcerrors.SetHeader(ctx, svcerrors.ClientCredentialsAssertionInvalid)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(invalidClient)

		return
	}

	if err := r.jti.Set(ctx, claims.ID, true); err != nil {
		// continue without saving JTI
		ctx.Log().Error("failed to save JTI in cache", zap.Error(err))
	}

	if client, err := r.IDAuth().Clients().GetClient(claims.Subject); err == nil && client != nil &&
		client.Metadata["token_binding"] == "dpop" && jkt == "" {
		svcerrors.SetHeader(ctx, svcerrors.TokenDPoPProofMissing)
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(invalidDPoPProof)

		return
	}

	var sessMeta map[string]string

	tokenType := "Bearer"
	if jkt != "" {
		tokenType = "DPoP"
		sessMeta = map[string]string{"dpop_jkt": jkt}
	}

	sessID := ulid.Make().String()
	now := time.Now().UTC()
	roles := []*core.RoleEntity{
		{
			ID:   "system",
			Code: "system",
			Name: "System",
		},
	}

	sess, err := r.IDAuth().Session().Create(ctx, &core.Session{
		ID:      sessID,
		Subject: "SYSTEM",
		Rights: []*core.GrantedRightListEntity{
			{
				RoleID:    roles[0].ID,
				RightCode: req.Scope,
			},
		},
		// TODO: Personalize system user
		// Code:         token.PersonCode,
		LastAccessed: &now,
		State:        string(core.SessionStateAuthorized),
		Role:         roles[0],
		Roles:        roles,
		Metadata:     sessMeta,
	})
	if err != nil {
		ctx.Log().Error("failed to create session", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:token:sessionCreateFailed"))

		return
	}

	ctx.JSON(&response.TokenResponse{
		AccessToken: sess.ID,
		TokenType:   tokenType,
		ExpiresIn:   core.GetSecondsToLive(r.Config().SessionTimeout, sess.LastAccessed),
	})
}
