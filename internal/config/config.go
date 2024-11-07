package config

import (
	"context"
	"fmt"

	scfg "github.com/ihippik/config"
	"github.com/sethvargo/go-envconfig"
)

type Config struct {
	Logger     *scfg.Logger `env:",prefix=LOG_"`
	Monitoring scfg.Monitoring
}

func InitConfig(ctx context.Context, path string) (*Config, error) {
	var cfg Config

	if err := envconfig.Process(ctx, &cfg); err != nil {
		return nil, fmt.Errorf("process: %w", err)
	}

	return &cfg, nil
}
