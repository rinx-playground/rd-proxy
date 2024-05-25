package proxy

import (
	"net"
	"os"

	"github.com/rinx-playground/rd-proxy/pkg/proxy/server"
	"github.com/urfave/cli/v2"
)

var flags = []cli.Flag{
	&cli.StringFlag{
		Name:  "port",
		Usage: "server port",
		Value: "8000",
	},
	&cli.StringFlag{
		Name:  "policy-file",
		Usage: "policy rego file",
		Value: "",
	},
}

func NewCommand() *cli.Command {
	return &cli.Command{
		Name:   "proxy",
		Usage:  "TBW",
		Flags:  flags,
		Action: run,
	}
}

func run(c *cli.Context) error {
	policy, err := readPolicyFile(c.String("policy-file"))
	if err != nil {
		return err
	}

	server, err := server.New(&server.Config{
		Addr:   net.JoinHostPort("", c.String("port")),
		Policy: policy,
	})
	if err != nil {
		return err
	}

	return server.Start(c.Context)
}

func readPolicyFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}

	bs, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return string(bs), nil
}
