package main

import (
	"fmt"
	"log"
)

func main() {
	cfg := LoadConfig()
	log.Printf("Bulletin Board starting on %s", cfg.ListenAddr)
	fmt.Println("Database:", cfg.DatabaseURL)
}
