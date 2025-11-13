package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/lescuer97/nostr-oicd/storage"
	"github.com/lescuer97/nostr-oicd/storage/database"
	"github.com/lescuer97/nostr-oicd/vertex"
	"github.com/lescuer97/nostr-oicd/web"
)

func main() {
	// Load config from environment
	// cfg := config.LoadFromEnv()

	// Open DB using our helper
	db, err := database.Open("./database.db")
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	err = database.RunMigrations(db)
	if err != nil {
		log.Fatalf("could not run migration: %v", err)
	}

	storage, err := storage.NewStorage(db)
	if err != nil {
		log.Fatalf("storage.NewStorage(db). %v", err)
	}

	// Ensure a default configuration exists
	if err := ensureConfiguration(context.Background(), &storage); err != nil {
		log.Fatalf("failed to ensure default configuration: %v", err)
	}

	config, err := storage.GetConfigurationWithNsec(context.Background())
	if err != nil {
		log.Fatalf("storage.GetConfigurationWithNsec(context.Background()). %v", err)
	}

	server := web.Server{
		Storage: &storage,
	}

	if config.RegistrationType == "open" {
		if config.Nsec == nil {
			log.Panicf("you don't have an nsec in your configuration. This should have never happened because it should have been required when making the registration type opened")
		}

		vrt, err := vertex.NewVertexChecker(*config.Nsec)
		if err != nil {
			log.Fatalf("vertex.NewVertexChecker(): %v", err)
		}

		server.Vertex = vrt
	}

	r := web.SetupServer(&server)
	srv := &http.Server{
		Addr:    ":" + "8082",
		Handler: r,
	}

	go func() {
		log.Printf("starting server on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// log.Printf("/routes: %+v", router.Routes())
	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	<-ctx.Done()

	log.Println("shutting down gracefully, press Ctrl+C again to force")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("server forced to shutdown: %v", err)
	}

	log.Println("server exiting")
}

// ensureConfiguration checks if a configuration exists in the database.
// If it doesn't exist, it creates a default one with:
// - RegistrationType: manual
// - MaxClients: 5
// - MaxUsers: 1000
func ensureConfiguration(ctx context.Context, store *storage.Storage) error {
	// Try to get the current configuration
	config, err := store.GetConfiguration(ctx)
	if err == nil && config != nil {
		// Configuration exists, no need to create one
		log.Println("Configuration already exists")
		return nil
	}

	// Configuration doesn't exist, create a default one
	defaultConfig := &storage.Configuration{
		RegistrationType: "manual",
		MaxClients:       5,
		MaxUsers:         1000,
		LastUpdated:      uint64(time.Now().Unix()),
	}

	log.Println("Creating default configuration...")
	if err := store.UpdateConfiguration(ctx, defaultConfig); err != nil {
		return fmt.Errorf("failed to create default configuration: %w", err)
	}

	log.Println("Default configuration created successfully")
	return nil
}
