// Package app is the composition root of the authorization service running on its own. It is a
// package rather than a main so a test can build the routes without a listener.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/applicaset/buildset/authz"
	"github.com/applicaset/buildset/authz/backend"
	"github.com/applicaset/buildset/authz/httpapi"
	"github.com/applicaset/buildset/pkg/config"
	"github.com/applicaset/buildset/pkg/serve"
	"github.com/applicaset/buildset/pkg/storage"
)

// schema is the Postgres schema this service owns. SQLite ignores it.
const schema = "authz"

type Config struct {
	config.Server

	Log      config.Log
	Database storage.Config
}

func LoadConfig(ctx context.Context) (*Config, error) {
	log, err := config.LoadLog()
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Server:   config.LoadServer(),
		Log:      log,
		Database: storage.Load(),
	}

	if err := cfg.Validate(ctx); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate(ctx context.Context) error {
	if err := c.Server.Validate(ctx); err != nil {
		return err
	}

	return c.Database.Validate()
}

type Service struct {
	handle *storage.Handle
	routes http.Handler
}

func New(ctx context.Context, cfg *Config, logger *slog.Logger) (*Service, error) {
	handle, err := storage.OpenHandle(ctx, cfg.Database, schema)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	repository, err := backend.New(ctx, cfg.Database.Driver, handle)
	if err != nil {
		_ = handle.Close()

		return nil, fmt.Errorf("build authz repository: %w", err)
	}

	handler, err := httpapi.NewHandler(authz.NewService(repository), logger)
	if err != nil {
		_ = handle.Close()

		return nil, fmt.Errorf("build authz handler: %w", err)
	}

	mux := http.NewServeMux()
	handler.Register(mux)

	return &Service{handle: handle, routes: mux}, nil
}

func (s *Service) Routes() http.Handler { return s.routes }

func (s *Service) Ping(ctx context.Context) error { return s.handle.Ping(ctx) }

func (s *Service) Close() error { return s.handle.Close() }

func Run(ctx context.Context) error {
	cfg, err := LoadConfig(ctx)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := serve.NewLogger(cfg.Log)
	slog.SetDefault(logger)

	service, err := New(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		if err := service.Close(); err != nil {
			logger.ErrorContext(ctx, "close service", slog.Any("error", err))
		}
	}()

	return serve.Run(ctx, serve.Options{
		Name:            "authz",
		Address:         cfg.Address(),
		ShutdownTimeout: cfg.ShutdownTimeout,
		Logger:          logger,
		Routes:          service.Routes(),
		Ready:           service.Ping,
		// No browser reaches this service, so there is no cross-origin form to protect. Callers
		// are sibling services, so their request identifier is kept.
		CrossOrigin:    false,
		TrustRequestID: true,
	})
}
