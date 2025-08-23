package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"sso/internal/domain/models"
	"sso/internal/storage"

	"github.com/mattn/go-sqlite3"
)

type Storage struct {
	db *sql.DB
}

// New creates a new instance of SQLite storage
func New(storagePath string) (*Storage, error) {
	const op = "storage.sqlite.New"

	db, err := sql.Open("sqlite3", storagePath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{db: db}, nil
}

func (s *Storage) SaveUser(
	ctx context.Context,
	email string, passHash []byte,
	firstName string,
	lastName string,
	middleName string,
) (int64, error) {
	const op = "storage.sqlite.SaveUser"

	stmp, err := s.db.Prepare(
		"INSERT INTO users (email, pass_hash, first_name, last_name, middle_name) VALUES (?, ?, ?, ?, ?)",
	)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	res, err := stmp.ExecContext(ctx, email, passHash, firstName, lastName, middleName)
	if err != nil {
		var sqliteErr sqlite3.Error

		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

// User return user by email
func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.sqlite.User"

	stmp, err := s.db.Prepare(
		"SELECT id, email, pass_hash, first_name, last_name, middle_name FROM users WHERE email = ?",
	)
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	res := stmp.QueryRowContext(ctx, email)

	var user models.User
	err = res.Scan(&user.ID, &user.Email, &user.PassHash, &user.FirstName, &user.LastName, &user.MiddleName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, storage.ErrUserNotFound
		}

		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	return user, nil
}

// UserRole returns role of the user
func (s *Storage) UserRole(ctx context.Context, userID int64) (string, error) {
	const op = "storage.sqlite.UserRole"

	stmp, err := s.db.Prepare(
		"SELECT r.role FROM roles r INNER JOIN enrollments en ON r.id = en.role_id WHERE en.user_id = ?",
	)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	res := stmp.QueryRowContext(ctx, userID)

	var role string
	err = res.Scan(&role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", storage.ErrUserNotFound
		}

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return role, nil
}

func (s *Storage) App(ctx context.Context, appID int) (models.App, error) {
	const op = "storage.sqlite.App"

	stmp, err := s.db.Prepare("SELECT id, name, secret FROM apps WHERE id = ?")
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	res := stmp.QueryRowContext(ctx, appID)

	var app models.App

	err = res.Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, storage.ErrAppNotFound
		}

		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}
