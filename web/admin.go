package web

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/form/v4"
	"github.com/lescuer97/nostr-oicd/web/templates"
)

// NewSignupHandler creates a new signup handler
func NewAdminHandler(storage Storage) chi.Router {
	s := &adminHandler{
		storage: storage,
	}
	router := chi.NewRouter()
	router.Get("/client/{id}", s.clientEditFormById)
	router.Get("/add_client", s.addClientForm)

	router.Post("/add_client", s.addClient)
	router.Post("/client/{id}", s.editClient)
	// router.Post("/", s.processSignup)
	return router
}

type adminHandler struct {
	storage Storage
}

func (s *adminHandler) clientEditFormById(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	client, err := s.storage.GetClientByClientID(r.Context(), id)
	if err != nil {
		log.Printf("\n error: %+v", errors.Is(err, sql.ErrNoRows))
		if errors.Is(err, sql.ErrNoRows) {
			templates.NotFoundPage("Client id not found for modification").Render(r.Context(), w)
			return
		}
		slog.Error("Client id does not exist", slog.String("error", err.Error()))
		writeHtmlNotification(templates.NotifInfo{
			Msg:  "Client not found",
			Type: notificationTypeError,
		}, r, w)
		return
	}

	// Convert op.Client interface to ClientFormData
	clientInfo := templates.ClientToFormData(client)
	templates.ClientFormPage(&clientInfo).Render(r.Context(), w)
}

func (s *adminHandler) addClientForm(w http.ResponseWriter, r *http.Request) {
	templates.ClientFormPage(nil).Render(r.Context(), w)
}

var decoder = form.NewDecoder()

func (s *adminHandler) addClient(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		slog.Error("Failed to parse form", slog.String("error", err.Error()))
		writeHtmlNotification(templates.NotifInfo{
			Msg:  "Invalid form data",
			Type: notificationTypeError,
		}, r, w)
		return
	}

	// Decode into your struct
	var user templates.ClientFormData
	if err := decoder.Decode(&user, r.Form); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Use the data
	fmt.Printf( "Received user: %+v", user)


	// Success - show success message
	writeHtmlNotification(templates.NotifInfo{
		Msg:  "Client created successfully (database save pending implementation)",
		Type: notificationTypeSuccess,
	}, r, w)
}

func (s *adminHandler) editClient(w http.ResponseWriter, r *http.Request) {
	templates.ClientFormPage(nil).Render(r.Context(), w)
}

// parseIntOrDefault parses a string to int, returning a default value on error
func parseIntOrDefault(s string, defaultVal int) int {
	val, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return val
}

// generateClientSecret generates a secure random client secret
func generateClientSecret() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to a simpler approach if crypto/rand fails
		return "fallback-secret-" + strconv.FormatInt(time.Now().Unix(), 10)
	}
	return base64.URLEncoding.EncodeToString(b)
}
