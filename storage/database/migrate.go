package database

import (
	"database/sql"
	"embed"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"
)

func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	// PRAGMA for WAL mode and busy timeout
	_, err = db.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
	if err != nil {
		log.Printf("warning: failed to set pragmas: %v", err)
	}
	return db, nil
}

//go:embed migrations/*.sql
var embedMigrations embed.FS //

func RunMigrations(db *sql.DB, migrationsDir string) error {
	goose.SetBaseFS(embedMigrations)
	if err := goose.SetDialect("sqlite3"); err != nil {
		return fmt.Errorf(`goose.SetDialect(string(databaseType)). %w`, err)
	}

	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf(`goose.Up(db, "migrations"). %w`, err)
	}

	return nil
}
