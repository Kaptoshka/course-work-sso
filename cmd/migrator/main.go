package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	// Library for migrations
	"github.com/golang-migrate/migrate/v4"
	// Driver for migrations in SQLite3
	_ "github.com/golang-migrate/migrate/v4/database/sqlite3"
	// Driver for getting migrations from files
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	storagePath, migrationsPath, migrationsTable := fetchMigratorPaths()
	if storagePath == "" || migrationsPath == "" {
		panic("storage-path and migrations-path cannot be empty")
	}

	m, err := migrate.New(
		"file://"+migrationsPath,
		fmt.Sprintf("sqlite3://%s?x-migrations-table=%s", storagePath, migrationsTable),
	)
	if err != nil {
		panic(err)
	}
	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Printf("no migrations to apply")

			return
		}

		panic(err)
	}
}

// fetchMigratorPaths fetches the paths for the storage, migration, and migrations table.
// Priority: flag > env > default
// storagePath and migrationPath cannot be empty
// Default value: storagePath: , migrationPath: , migrationsTable: "migrations"
func fetchMigratorPaths() (string, string, string) {
	var storagePath, migrationsPath, migrationsTable string

	flag.StringVar(&storagePath, "storage-path", "", "path to the storage")
	flag.StringVar(&migrationsPath, "migrations-path", "", "path to migrations")
	flag.StringVar(&migrationsTable, "migrations-table", "migrations", "name of migrations table")
	flag.Parse()

	if storagePath == "" {
		storagePath = os.Getenv("STORAGE_PATH")
	}
	if migrationsPath == "" {
		migrationsPath = os.Getenv("MIGRATIONs_PATH")
	}

	return storagePath, migrationsPath, migrationsTable
}
