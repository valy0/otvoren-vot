package main

import (
	"fmt"
	"log"

	"github.com/valy0/otvoren-vot/machine/ballot"
)

func main() {
	cfg := LoadConfig()
	log.Printf("Voting machine starting — station %s", cfg.StationID)

	queue := ballot.NewQueue(cfg.DataDir)

	// In production: full-screen kiosk UI
	// For now: log the configuration
	fmt.Printf("Station: %s\n", cfg.StationID)
	fmt.Printf("Collection server: %s\n", cfg.CollectionURL)
	fmt.Printf("Parties: %d\n", cfg.NumParties)
	fmt.Printf("Data directory: %s\n", cfg.DataDir)
	fmt.Printf("Queue size: %d\n", queue.Size())

	log.Println("Machine ready (CLI mode — kiosk UI not yet implemented)")
}
