package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	scfg "github.com/ihippik/config"
	"github.com/urfave/cli/v2"

	"github.com/ihippik/risk-radar/internal/config"
	"github.com/ihippik/risk-radar/internal/radar"
)

func main() {
	version := scfg.GetVersion()

	app := &cli.App{
		Name:    "RiskRadar",
		Usage:   "check for security events",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Value:   "config.yml",
				Aliases: []string{"c"},
				Usage:   "path to config file",
			},
		},
		Action: func(c *cli.Context) error {
			ctx, cancel := signal.NotifyContext(c.Context, syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			cfg, err := config.InitConfig(ctx, c.String("config"))
			if err != nil {
				return fmt.Errorf("get config: %w", err)
			}

			logger := scfg.InitSlog(cfg.Logger, version, cfg.Monitoring.SentryDSN != "")
			svc := radar.NewService(logger, nil)

			return svc.Start(ctx)
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
