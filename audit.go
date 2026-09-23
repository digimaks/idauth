// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"net/http"

	"azugo.io/azugo"
	ahttp "azugo.io/core/http"
	"github.com/lx-lib/lx-idauth/core"
	"github.com/lx-lib/lx-idauth/core/util"
	"github.com/nobid-lsp-latvia/go-audit"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

type AuditProvider interface {
	SaveEvent(ctx *azugo.Context, event *core.AuditEvent) (*http.Response, error)
}

type auditProvider struct {
	auditProvider audit.Audit
}

func (ap auditProvider) SaveEvent(ctx *azugo.Context, event *core.AuditEvent) (*http.Response, error) {
	endpoint := ctx.RouterPath()
	ip := ctx.IP().String()
	userAgent := ctx.UserAgent()
	events := event.Events

	for i := range *events {
		auditRequest := audit.AuditRequest{
			ClientID: "idauth",
			Endpoint: &endpoint,
			Action:   *util.PtrString(*(*events)[i].EventCode),
			Person: &audit.Person{
				GivenName:  &event.Session.FirstName,
				FamilyName: &event.Session.LastName,
				Identifier: &event.Session.Subject,
			},
			IPAddress: &ip,
			UserAgent: &userAgent,
		}

		err := ap.auditProvider.PersonRequest(ctx, auditRequest, ahttp.WithHeader(fasthttp.HeaderAuthorization, "Bearer "+event.Session.ID))
		if err != nil {
			ctx.StatusCode(500)
			ctx.Log().Error("Failed to save audit event", zap.Error(err))

			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Status:     "500 SERVER ERROR",
				Body:       nil,
			}, nil
		}
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       nil,
	}, nil
}

func NewAuditProvider(audit audit.Audit) core.AuditProvider {
	return auditProvider{
		auditProvider: audit,
	}
}
