package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/lescuer97/nostr-oicd/storage"
	"github.com/lescuer97/nostr-oicd/storage/database"
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
	r := web.SetupServer(&storage)

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
