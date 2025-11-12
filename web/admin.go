package web

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/form/v4"
	"github.com/google/uuid"
	"github.com/lescuer97/nostr-oicd/storage"
	"github.com/lescuer97/nostr-oicd/web/templates"
)

var decoder = form.NewDecoder()

type administration interface {
	AddClient(ctx context.Context, client storage.Client) error
	EditClient(ctx context.Context, client storage.Client) error

	GetUserById(ctx context.Context, id string) (*storage.User, error)
	// AddUser(ctx context.Context, client storage.User) error
	EditUser(ctx context.Context, client storage.User) error

	// New methods for configuration management
	GetConfiguration(ctx context.Context) (*storage.Configuration, error)
	UpdateConfiguration(ctx context.Context, config *storage.Configuration) error
}

// NewSignupHandler creates a new signup handler
func NewAdminHandler(storage Storage) chi.Router {
	s := &adminHandler{
		storage: storage,
	}
	router := chi.NewRouter()

	// Existing routes
	router.Get("/client/{id}", s.clientEditFormById)
	router.Get("/add_client", s.addClientForm)

	router.Post("/add_client", s.addClient)
	router.Post("/client/{id}", s.editClient)

	router.Get("/user/{id}", s.editUserForm)
	router.Get("/add_user", s.addUserForm)

	router.Post("/add_user", s.addUserHandler)
	router.Post("/user/{id}", s.editUserHandler)

	// New dashboard routes
	router.Get("/", s.dashboard)

	router.Get("/configuration", s.configuration)

	// templs component
	router.Get("/clients", s.clientsList)
	router.Get("/users", s.usersList)

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
	fmt.Printf("Received user: %+v", user)

	client := templates.FormDataToStorageClient(&user, "")

	if client == nil {
		log.Panicf("client should have never been nil")
	}

	err := s.storage.AddClient(r.Context(), *client)
	if err != nil {
		slog.Error("s.storage.AddClient", slog.String("error", err.Error()))
		writeHtmlNotification(templates.NotifInfo{
			Msg:  "Could not add client",
			Type: notificationTypeError,
		}, r, w)

	}

	// Success - show success message
	writeHtmlNotification(templates.NotifInfo{
		Msg:  "Client created successfully (database save pending implementation)",
		Type: notificationTypeSuccess,
	}, r, w)
}

func (s *adminHandler) editClient(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
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

	if id != user.ClientID {
		slog.Error("trying to editing the wrong client")
		writeHtmlNotification(templates.NotifInfo{
			Msg:  "Trying to change a channel id without access",
			Type: notificationTypeError,
		}, r, w)
		return
	}

	// Use the data
	fmt.Printf("Received user: %+v", user)

	client := templates.FormDataToStorageClient(&user, "")

	if client == nil {
		log.Panicf("client should have never been nil")
	}
	err := s.storage.EditClient(r.Context(), *client)
	if err != nil {
		slog.Error("s.storage.AddClient", slog.String("error", err.Error()))
		writeHtmlNotification(templates.NotifInfo{
			Msg:  "Could not add client",
			Type: notificationTypeError,
		}, r, w)

	}

	// Success - show success message
	writeHtmlNotification(templates.NotifInfo{
		Msg:  "Client created successfully (database save pending implementation)",
		Type: notificationTypeSuccess,
	}, r, w)

}

func (s *adminHandler) editUserForm(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	user, err := s.storage.GetUserById(r.Context(), id)
	if err != nil {
		log.Printf("\n error: %+v", errors.Is(err, sql.ErrNoRows))
		if errors.Is(err, sql.ErrNoRows) {
			templates.NotFoundPage("User id not found for modification").Render(r.Context(), w)
			return
		}
		slog.Error("User id does not exist", slog.String("error", err.Error()))
		writeHtmlNotification(templates.NotifInfo{
			Msg:  "User not found",
			Type: notificationTypeError,
		}, r, w)
		return
	}

	// Convert storage.User to UserFormData
	userFormData := templates.StorageUserToFormData(user)
	templates.UserFormPage(&userFormData).Render(r.Context(), w)
}

func (s *adminHandler) editUserHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
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
	var formUser templates.UserFormData
	if err := decoder.Decode(&formUser, r.Form); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	if id != formUser.ID {
		slog.Error("trying to editing the wrong client")
		writeHtmlNotification(templates.NotifInfo{
			Msg:  "Trying to change a channel id without access",
			Type: notificationTypeError,
		}, r, w)
		return
	}

	user, err := templates.FormDataToStorageUser(&formUser)
	if err != nil {
		slog.Error("parsing user for editing went wrong", slog.Any("error", err))
		writeHtmlNotification(templates.NotifInfo{
			Msg:  "parsing user for editing went wrong",
			Type: notificationTypeError,
		}, r, w)
		return
	}

	if user == nil {
		log.Panicf("client should have never been nil")
	}

	err = s.storage.EditUser(r.Context(), *user)
	if err != nil {
		slog.Error("s.storage.EditUser(r.Context(), *user)", slog.String("error", err.Error()))
		writeHtmlNotification(templates.NotifInfo{
			Msg:  "Could not add user",
			Type: notificationTypeError,
		}, r, w)

	}

	// Success - show success message
	writeHtmlNotification(templates.NotifInfo{
		Msg:  "User edited successfully",
		Type: notificationTypeSuccess,
	}, r, w)
}

func (s *adminHandler) addUserForm(w http.ResponseWriter, r *http.Request) {
	templates.UserFormPage(nil).Render(r.Context(), w)
}

func (s *adminHandler) addUserHandler(w http.ResponseWriter, r *http.Request) {
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
	var formUser templates.UserFormData
	if err := decoder.Decode(&formUser, r.Form); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	user, err := templates.FormDataToStorageUser(&formUser)
	if err != nil {
		slog.Error("parsing user for editing went wrong", slog.Any("error", err))
		writeHtmlNotification(templates.NotifInfo{
			Msg:  "parsing user for editing went wrong",
			Type: notificationTypeError,
		}, r, w)
		return
	}

	user.ID = uuid.NewString()
	if user == nil {
		log.Panicf("client should have never been nil")
	}
	user.Active = true

	err = s.storage.AddUser(r.Context(), *user)
	if err != nil {
		slog.Error("s.storage.AddUser", slog.String("error", err.Error()))
		writeHtmlNotification(templates.NotifInfo{
			Msg:  "Could not add user",
			Type: notificationTypeError,
		}, r, w)

	}

	// Success - show success message
	writeHtmlNotification(templates.NotifInfo{
		Msg:  "Created user successfully",
		Type: notificationTypeSuccess,
	}, r, w)
}

func (s *adminHandler) dashboard(w http.ResponseWriter, r *http.Request) {
	templates.Dashboard().Render(r.Context(), w)
}

func (s *adminHandler) configuration(w http.ResponseWriter, r *http.Request) {
	templates.Dashboard().Render(r.Context(), w)
}

func (s *adminHandler) clientsList(w http.ResponseWriter, r *http.Request) {
	// For now, return empty list - will be populated from storage later

	clientsDb, err := s.storage.GetAllClients(r.Context())
	if err != nil {
		slog.Error("s.storage.GetAllClients(r.Context())", slog.String("error", err.Error()))
		writeHtmlNotification(templates.NotifInfo{
			Msg:  "Could not get list of clients",
			Type: notificationTypeError,
		}, r, w)
	}

	clients := make([]templates.ClientFormData, len(clientsDb))

	for i, clientDb := range clientsDb {
		client := templates.ClientToFormData(&clientDb)
		clients[i] = client
	}

	templates.ClientList(clients).Render(r.Context(), w)
}

func (s *adminHandler) usersList(w http.ResponseWriter, r *http.Request) {
	usersDb, err := s.storage.GetAllUsers(r.Context())
	if err != nil {
		slog.Error("s.storage.GetAllUsers(r.Context())", slog.String("error", err.Error()))
		writeHtmlNotification(templates.NotifInfo{
			Msg:  "Could not get list of users",
			Type: notificationTypeError,
		}, r, w)

	}

	users := make([]templates.UserFormData, len(usersDb))
	for i, userDb := range usersDb {
		user := templates.StorageUserToFormData(&userDb)
		users[i] = user
	}

	templates.UserList(users).Render(r.Context(), w)
}
