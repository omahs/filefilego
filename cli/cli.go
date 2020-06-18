package main

import (
	"github.com/urfave/cli"
)

var (
	AppHelpTemplate = `NAME:
{{.Name}} - {{.Usage}}
Copyright 2020 The FileFileGo team
USAGE:
{{.HelpName}} {{if .VisibleFlags}}[global options]{{end}}{{if .Commands}} command [command options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}
{{if len .Authors}}
AUTHOR:
{{range .Authors}}{{ . }}{{end}}
{{end}}{{if .Version}}
VERSION:
  {{.Version}}
  {{end}}{{if .Commands}}
COMMANDS:
{{range .Commands}}{{if not .HideHelp}}   {{join .Names ", "}}{{ "\t"}}{{.Usage}}{{ "\n" }}{{end}}{{end}}{{end}}{{if .VisibleFlags}}
GLOBAL OPTIONS:
{{range .VisibleFlags}}{{.}}
{{end}}{{end}}{{if .Copyright }}
COPYRIGHT:
   {{.Copyright}}
{{end}}
`
)

// NewApp
func NewApp() *cli.App {
	app := cli.NewApp()
	app.CustomAppHelpTemplate = AppHelpTemplate
	app.Name = "FileFileGo"
	app.Usage = "command line interface"
	app.Copyright = "Copyright 2020 The FileFileGo Authors"

	return app
}
