package app

import (
	"log/slog"
	"time"

	grpcapp "sso/internal/app/grpc"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(
	log *slog.Logger,
	grpcPort int,
	storagePath string,
	tokeTTL time.Duration,
) *App {
	// TODO: init storage
	//
	// TOOD: init auth service
	//
	grpcApp := grpcapp.New(log, grpcPort)

	return &App{
		GRPCSrv: grpcApp,
	}
}
