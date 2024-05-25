package main

import (
	"log/slog"
	"os"

	"github.com/rinx-playground/rd-proxy/pkg/entrypoint/client"
	"github.com/rinx-playground/rd-proxy/pkg/entrypoint/proxy"
	cli "github.com/urfave/cli/v2"
)

var Version = "unknown"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cli.VersionPrinter = versionPrinter

	app := &cli.App{
		Name:  "rd-proxy",
		Usage: "TBW",
		Commands: []*cli.Command{
			client.NewCommand(),
			proxy.NewCommand(),
		},
		Version: Version,
	}

	err := app.Run(os.Args)
	if err != nil {
		slog.Error("error", "error", err)
	}
}

func versionPrinter(c *cli.Context) {
	slog.Info("version", "version", c.App.Version)
}
