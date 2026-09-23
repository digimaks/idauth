// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"context"
	"strings"
	"time"

	"github.com/digimaks/idauth"
	"github.com/digimaks/idauth/clientattestation"
	"github.com/digimaks/idauth/dpop"
	"github.com/digimaks/idauth/edim"
	"github.com/digimaks/idauth/oauth2generic"
	"github.com/digimaks/idauth/smartid"

	"azugo.io/azugo"
	"azugo.io/azugo/token/nonce"
	"azugo.io/core/cache"
	"github.com/digimaks/go-verifier"
)

type router struct {
	*idauth.App
	edimInst           *edim.Inst
	edimSameDeviceInst *edim.Inst
	smardIDInst        *smartid.Inst
	jti                cache.Instance[bool]
	dpop               *dpop.Validator
	attest             *clientattestation.Verifier
}

// metadataOverrideRouter wraps azugo.Router, replacing the handler registered
// for a single GET path with a fixed handler. Used to substitute idauth's own
// well-known metadata route for ours as it registers it (see Init), before
// any auth middleware it adds later can attach to the override.
type metadataOverrideRouter struct {
	azugo.Router
	path    string
	handler azugo.RequestHandler
}

func (o *metadataOverrideRouter) Get(path string, handler azugo.RequestHandler) {
	if path == o.path {
		handler = o.handler
	}

	o.Router.Get(path, handler)
}

func Init(app *idauth.App) error {
	jti, err := cache.Create[bool](app.Cache(), "system-token-jti", cache.DefaultTTL(5*time.Minute))
	if err != nil {
		return err
	}

	dpopJTI, err := cache.Create[bool](app.Cache(), "dpop-jti", cache.DefaultTTL(5*time.Minute))
	if err != nil {
		return err
	}

	r := &router{
		App: app,
		jti: jti,
	}

	r.dpop = dpop.NewValidator(dpop.Config{
		AcceptedHTUs: append(
			[]string{app.Config().IdauthPublicURL + "/api/1.0/token"},
			app.Config().DPoP.AcceptedHTU...,
		),
		IATWindow: app.Config().DPoP.IATWindow,
		ReplayCheck: func(ctx context.Context, jti string) (bool, error) {
			seen, err := dpopJTI.Get(ctx, jti)
			if err != nil {
				return false, nil //nolint:nilerr
			}

			if seen {
				return true, nil
			}

			return false, dpopJTI.Set(ctx, jti, true)
		},
	})

	attestJTI, err := cache.Create[bool](app.Cache(), "client-attestation-jti", cache.DefaultTTL(5*time.Minute))
	if err != nil {
		return err
	}

	anchors, err := app.Config().ClientAttestation.LoadTrustAnchors()
	if err != nil {
		return err
	}

	if anchors != nil {
		r.attest, err = clientattestation.NewVerifier(clientattestation.Config{
			TrustAnchors: anchors,
			Audiences: append(
				[]string{
					app.Config().IdauthPublicURL + "/api/1.0/token",
					app.Config().IdauthPublicURL + "/par",
				},
				app.Config().ClientAttestation.AcceptedAudiences...,
			),
			IATWindow:         app.Config().ClientAttestation.IATWindow,
			RequireKeyBinding: app.Config().ClientAttestation.RequireKeyBinding,
			ReplayCheck: func(ctx context.Context, jti string) (bool, error) {
				seen, err := attestJTI.Get(ctx, jti)
				if err != nil {
					return false, nil //nolint:nilerr
				}

				if seen {
					return true, nil
				}

				return false, attestJTI.Set(ctx, jti, true)
			},
		})
		if err != nil {
			return err
		}
	}

	// this is set before bind, so we have separate logic for bearer token and basic authorization
	r.Post("/api/1.0/token", r.token)
	r.Get("/authorizationV3", r.authorizationV3)
	r.Post("/par", r.par)
	r.Get("/edim/verifier/{presentID}", r.verified)
	r.Get(edim.SameDeviceReturnPath, r.edimSameDeviceReturn)
	r.Post("/smartid/login", r.smartIDLogin)
	r.Get("/smartid/verifier/{sessionID}", r.smartIDVerifier)
	r.Get("/healthz", r.healthz)

	r.Post("/preauth_generate", r.preauthGenerate)
	r.Post("/introspection", r.introspection)

	r.Get("/.well-known/oauth-authorization-server/idauth", r.oauthAuthorizationServerMeta)
	r.Get("/.well-known/assetlinks.json", r.assetLinks)
	r.Get("/.well-known/apple-app-site-association", r.appleAppSiteAssociation)

	// idauth.IDAuth.Bind registers its own minimal metadata handler at the
	// standard "/.well-known/oauth-authorization-server" path as its very
	// first route, then later calls Use(AuthorizeBearer) which applies to
	// every route it registers afterwards. metadataOverrideRouter swaps that
	// one Get call for our richer handler (DPoP, PAR, pre-authorized_code,
	// client attestation, ...) at the exact point it's registered, so OID4VCI
	// clients resolving the standard path see the same metadata as the
	// "/idauth"-suffixed alias, without picking up AuthorizeBearer.
	app.IDAuth().Bind(&metadataOverrideRouter{
		Router:  r,
		path:    "/.well-known/oauth-authorization-server",
		handler: r.oauthAuthorizationServerMeta,
	})

	edimNonceCache, err := cache.Create[bool](app.Cache(), "edim-nonce", cache.DefaultTTL(10*time.Minute))
	if err != nil {
		return err
	}

	verifierInst, err := verifier.New(app.App, app.Config().Verifier, app.Log())
	if err != nil {
		return err
	}

	providerConfig, err := r.GetAuthProvider("edim")
	if err != nil {
		return err
	}

	if r.edimInst, err = edim.Bind(app.IDAuth(), verifierInst, app.Config().Verifier, providerConfig, nonce.NewCacheNonceStore(edimNonceCache), app.Audit(), app.AuthCodeStore()); err != nil {
		return err
	}

	providerConfig, err = r.GetAuthProvider("edim:same_device")
	if err != nil {
		return err
	}

	if r.edimSameDeviceInst, err = edim.Bind(app.IDAuth(), verifierInst, app.Config().Verifier, providerConfig, nil, app.Audit(), app.AuthCodeStore()); err != nil {
		return err
	}

	for id, cfg := range app.Config().OAuth2Generic {
		id := strings.ToLower(id)

		providerConfig, err := r.GetAuthProvider(id)
		if err != nil {
			return err
		}

		if err := oauth2generic.Bind(app.App, app.IDAuth(), cfg, providerConfig, cfg.AcrValues, app.Audit(), app.AuthCodeStore()); err != nil {
			return err
		}

		for _, variant := range cfg.Variants {
			variantID := id + ":" + strings.ToLower(variant.ID)

			variantProviderConfig, err := r.GetAuthProvider(variantID)
			if err != nil {
				return err
			}

			if err := oauth2generic.Bind(app.App, app.IDAuth(), cfg, variantProviderConfig, variant.AcrValues, app.Audit(), app.AuthCodeStore()); err != nil {
				return err
			}
		}
	}

	if r.smardIDInst, err = smartid.Bind(app.App, app.IDAuth(), app.Config().SmartID, app.Audit(), app.AuthCodeStore()); err != nil {
		return err
	}

	return nil
}

func (r *router) verified(ctx *azugo.Context) {
	r.edimInst.Verified(ctx)
}

func (r *router) edimSameDeviceReturn(ctx *azugo.Context) {
	r.edimSameDeviceInst.SameDeviceReturn(ctx)
}

func (r *router) smartIDLogin(ctx *azugo.Context) {
	r.smardIDInst.Login(ctx)
}

func (r *router) smartIDVerifier(ctx *azugo.Context) {
	r.smardIDInst.Verified(ctx)
}
