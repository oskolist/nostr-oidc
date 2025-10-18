package web

import (
	"database/sql"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
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

	router.Post("/add_client", s.addClientForm)
	router.Post("/client/{id}", s.clientEditFormById)
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

func (s *adminHandler) addClient(w http.ResponseWriter, r *http.Request) {
	// body, err := io.ReadAll(r.Body)
	// if err != nil {
	// 	return
	// }
	defer r.Body.Close()
	log.Printf("after body parse")

	// var nostrEvent templates.ClientFormData
	// err = json.Unmarshal(body, &nostrEvent)
	// templates.ClientFormPage(nil).Render(r.Context(), w)
}

func (s *adminHandler) editClient(w http.ResponseWriter, r *http.Request) {
	templates.ClientFormPage(nil).Render(r.Context(), w)
}
