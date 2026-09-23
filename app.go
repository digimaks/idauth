// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"github.com/digimaks/idauth/authorizationcode"
	"github.com/digimaks/idauth/store"
	idauth "github.com/lx-lib/lx-idauth"

	"azugo.io/azugo"
	"azugo.io/azugo/server"
	"azugo.io/opentelemetry"
	kitconfig "github.com/gmb-lib/go-platform-kit/config"
	"github.com/gmb-lib/go-platform-kit/platform"
	"github.com/lx-lib/lx-go-jsondb"
	idauth_app "github.com/lx-lib/lx-idauth/app"
	"github.com/lx-lib/lx-idauth/core"
	"github.com/nobid-lsp-latvia/go-audit"
	"github.com/spf13/cobra"
)

type App struct {
	*azugo.App

	idauth        *idauth.IDAuth
	config        *Configuration
	auditClient   audit.Audit
	authCodeStore *authorizationcode.Store
	authProvider  *authProvider
}

// New returns a new application instance.
func New(cmd *cobra.Command, configPath, version string) (*App, error) {
	config := NewConfiguration()
	config.SetConfigFile(configPath)

	a, err := server.New(cmd, server.Options{
		AppName:       "IDAuth Server",
		AppVer:        version,
		Configuration: config,
	})
	if err != nil {
		return nil, err
	}

	if err := platform.Setup(a, platform.Options{
		Config: &kitconfig.BaseConfiguration{Telemetry: config.Telemetry},
		TracingOptions: []opentelemetry.Option{
			opentelemetry.InstrumentationRecorder("db", jsondb.Tracing, jsondb.InstrumentationExec),
		},
		PublicErrors: true,
	}); err != nil {
		return nil, err
	}

	a.RouterOptions().CORS.SetHeaders("Accept", "Content-Type", "Authorization")

	ootStore, err := idauth_app.NewAzugoCacheOOTStore(a)
	if err != nil {
		return nil, err
	}

	corelationStore, err := idauth_app.NewAzugoCacheCorrelationStore(a)
	if err != nil {
		return nil, err
	}

	sessionStore, err := idauth.NewAzugoCacheSessionStore(a, config.SessionTimeout)
	if err != nil {
		return nil, err
	}

	clientStore, err := store.NewClientStore(a, config.Store)
	if err != nil {
		return nil, err
	}

	authCodeStore, err := authorizationcode.NewAuthCodeStore(a, config.AuthorizationCode)
	if err != nil {
		return nil, err
	}

	if err := loadOAuth2GenericConfig(config); err != nil {
		return nil, err
	}

	authProvider := newAuthProvider(config)

	sensitiveParams := map[string][]string{
		"GET /callback/eparaksts": {"code", "state"},
	}

	auditProvider := audit.New(config.Audit, sensitiveParams)

	auditMiddlewareProvider := NewAuditProvider(auditProvider)

	return &App{
		App: a,
		idauth: idauth.New(a).
			WithConfig(config).
			WithClientStore(clientStore).
			WithAuthProviderStore(authProvider).
			WithCorrelationStore(newCorrelationStore(corelationStore)).
			WithOOTStore(ootStore).
			WithSessionStore(sessionStore).
			WithAuthorizer(authProvider).
			WithAuditProvider(auditMiddlewareProvider),
		config:        config,
		auditClient:   auditProvider,
		authCodeStore: authCodeStore,
		authProvider:  authProvider,
	}, nil
}

func (a *App) Config() *Configuration {
	return a.config
}

func (a *App) IDAuth() *idauth.IDAuth {
	return a.idauth
}

func (a *App) Audit() audit.Audit {
	return a.auditClient
}

func (a *App) AuthCodeStore() *authorizationcode.Store {
	return a.authCodeStore
}

func (a *App) GetAuthProvider(name string) (*core.AuthProviderConfig, error) {
	return a.authProvider.GetProvider(name)
}
