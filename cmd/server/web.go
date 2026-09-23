// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"github.com/digimaks/idauth"
	"github.com/digimaks/idauth/routes"

	"azugo.io/azugo/server"
	"github.com/spf13/cobra"
)

var configPath string

// webCmd represents the web command.
var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Start web server",
	Long: `Web server is the only thing you need to run,
and it takes care of all the other things for you`,
	RunE: runWeb,
}

func runWeb(cmd *cobra.Command, _ []string) error {
	a, err := idauth.New(cmd, configPath, Version)
	if err != nil {
		return err
	}

	if err = routes.Init(a); err != nil {
		return err
	}

	server.Run(a)

	return nil
}

func init() {
	initRootCmd()
	RootCmd.AddCommand(webCmd)

	webCmd.Flags().StringVarP(&configPath,
		"config",
		"c",
		"",
		"Configuration file path")
}
