package client

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	"github.com/rancher/remotedialer"
	"github.com/rinx-playground/rd-proxy/pkg/config"
	"github.com/urfave/cli/v2"
)

var flags = []cli.Flag{
	&cli.StringFlag{
		Name:  "server",
		Usage: "proxy-connect websocket url",
		Value: "ws://localhost:8000/proxy-connect",
	},
	&cli.StringFlag{
		Name:  "id",
		Usage: "connection id",
		Value: "",
	},
	&cli.StringFlag{
		Name:  "port",
		Usage: "target port",
		Value: "",
	},
}

type opts struct {
	server string
	id     string
	port   string
}

func NewCommand() *cli.Command {
	return &cli.Command{
		Name:   "client",
		Usage:  "TBW",
		Flags:  flags,
		Action: run,
	}
}

func validate(c *cli.Context) (*opts, error) {
	server := c.String("server")
	if _, err := url.Parse(server); err != nil {
		return nil, errors.Errorf("invalid format of server: %s", err)
	}

	id := c.String("id")
	if id == "" {
		return nil, errors.New("id must be specified")
	}

	port := c.String("port")
	if port == "" {
		return nil, errors.New("port must be specified")
	}

	return &opts{
		server: server,
		id:     id,
		port:   port,
	}, nil
}

func run(c *cli.Context) error {
	ctx := c.Context

	opts, err := validate(c)
	if err != nil {
		return err
	}

	headers := http.Header{
		config.ProxyIDHeader:         []string{opts.id},
		config.ProxyMethodHeader:     []string{"register"},
		config.ProxyTargetPortHeader: []string{opts.port},
	}

	return remotedialer.ClientConnect(
		ctx,
		opts.server,
		headers,
		nil,
		func(string, string) bool { return true },
		onConnect,
	)
}

func onConnect(ctx context.Context, session *remotedialer.Session) error {
	slog.Info("connection established")

	return nil
}
