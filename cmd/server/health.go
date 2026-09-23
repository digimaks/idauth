// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/digimaks/idauth"

	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// healthCmd represents the health command.
var healthCmd = &cobra.Command{
	Use:           "health",
	Short:         "Check health of the server",
	Long:          `Check if the web server is running and responding to healthz request`,
	RunE:          runHealth,
	SilenceErrors: true,
}

func runHealth(cmd *cobra.Command, _ []string) error {
	a, err := idauth.New(cmd, configPath, Version)
	if err != nil {
		return err
	}

	req := fasthttp.AcquireRequest()
	req.Header.SetMethod(fasthttp.MethodGet)

	var uri string

	var hostPort string
	if a.Config().Server.HTTP.Enabled {
		hostPort = net.JoinHostPort(a.Config().Server.HTTP.Address, strconv.Itoa(a.Config().Server.HTTP.Port))
		uri = fmt.Sprintf("http://%s%s/healthz", hostPort, a.Config().Server.Path)
	} else {
		hostPort = net.JoinHostPort(a.Config().Server.HTTPS.Address, strconv.Itoa(a.Config().Server.HTTPS.Port))
		uri = fmt.Sprintf("https://%s%s/healthz", hostPort, a.Config().Server.Path)
	}

	req.SetRequestURI(uri)

	resp := fasthttp.AcquireResponse()
	client := &fasthttp.Client{}
	err = client.Do(req, resp)
	fasthttp.ReleaseRequest(req)

	if err != nil {
		fasthttp.ReleaseResponse(resp)
		a.Log().Error("failed to connect to the server", zap.Error(err))
		os.Exit(1)

		return nil
	}

	if resp.StatusCode() != fasthttp.StatusOK {
		if resp.StatusCode() != fasthttp.StatusFailedDependency {
			a.Log().Error("server returned unexpected status code", zap.Int("status", resp.StatusCode()))
		}

		fasthttp.ReleaseResponse(resp)
		os.Exit(1)

		return nil
	}

	fasthttp.ReleaseResponse(resp)

	return nil
}

func init() {
	initRootCmd()
	RootCmd.AddCommand(healthCmd)

	healthCmd.Flags().StringVarP(&configPath,
		"config",
		"c",
		"",
		"Configuration file path")
}
