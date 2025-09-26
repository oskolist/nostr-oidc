package oicdredesign

import (
	"log"

	"github.com/lescuer97/nostr-oicd/storage/database"
)

func main() {
	// Load config from environment
	// cfg := config.LoadFromEnv()

	// Open DB using our helper
	db, err := database.Open(".")
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()
}
