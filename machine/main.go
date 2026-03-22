package main

import (
	"log/slog"
	"os"

	"github.com/valy0/otvoren-vot/machine/ballot"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg := LoadConfig()
	slog.Info("voting machine starting", "station", cfg.StationID)

	queue := ballot.NewQueue(cfg.DataDir)

	// In production: full-screen kiosk UI
	// For now: log the configuration
	slog.Info("machine configured",
		"station", cfg.StationID,
		"collection_url", cfg.CollectionURL,
		"num_parties", cfg.NumParties,
		"data_dir", cfg.DataDir,
		"queue_size", queue.Size())

	slog.Info("machine ready (CLI mode, kiosk UI not yet implemented)")
}
