package web

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/securecookie"
	"github.com/lescuer97/nostr-oicd/web/templates"
	"github.com/nbd-wtf/go-nostr"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type deviceAuthenticate interface {
	op.DeviceAuthorizationStorage

	// GetDeviceAuthorizationByUserCode resturns the current state of the device authorization flow,
	// identified by the user code.
	GetDeviceAuthorizationByUserCode(ctx context.Context, userCode string) (*op.DeviceAuthorizationState, error)

	// CompleteDeviceAuthorization marks a device authorization entry as Completed,
	// identified by userCode. The Subject is added to the state, so that
	// GetDeviceAuthorizatonState can use it to create a new Access Token.
	CompleteDeviceAuthorization(ctx context.Context, userCode, subject string) error

	// DenyDeviceAuthorization marks a device authorization entry as Denied.
	DenyDeviceAuthorization(ctx context.Context, userCode string) error
	authenticate
}

type deviceLogin struct {
	storage Storage
	cookie  *securecookie.SecureCookie
}

func registerDeviceAuth(storage Storage, router chi.Router) {
	l := &deviceLogin{
		storage: storage,
		cookie:  securecookie.New(securecookie.GenerateRandomKey(32), nil),
	}

	router.HandleFunc("/", l.userCodeHandler)
	router.Post("/login", l.loginHandler)
	router.HandleFunc("/confirm", l.confirmHandler)
}

func (d *deviceLogin) userCodeHandler(w http.ResponseWriter, r *http.Request) {
	config, err := d.storage.GetConfiguration(r.Context())
	if err != nil {
		slog.Error("Failed to generate challenge", slog.String("error", err.Error()))
		http.Error(w, "Error generating challenge", http.StatusInternalServerError)
		return
	}

	err = r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		// renderUserCode(w, err)
		return
	}
	userCode := r.Form.Get("user_code")
	if userCode == "" {
		if prompt, _ := url.QueryUnescape(r.Form.Get("prompt")); prompt != "" {
			err = errors.New(prompt)
		}
		// renderUserCode(w, err)
		return
	}

	templates.Login(userCode, templates.DeviceLogin, config.RegistrationType != "manual").Render(r.Context(), w)
}

func redirectBack(w http.ResponseWriter, r *http.Request, prompt string) {
	values := make(url.Values)
	values.Set("prompt", url.QueryEscape(prompt))

	url := url.URL{
		Path:     "/device",
		RawQuery: values.Encode(),
	}
	http.Redirect(w, r, url.String(), http.StatusSeeOther)
}

const userCodeCookieName = "user_code"

type userCodeCookie struct {
	UserCode string
	UserId string
}

func (d *deviceLogin) loginHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	defer r.Body.Close()
	log.Printf("after body parse")

	var nostrEvent nostr.Event
	err = json.Unmarshal(body, &nostrEvent)
	if err != nil {
		slog.Debug(
			"Incorrect body",
			slog.String("error", err.Error()),
		)
		http.Error(w, "body needs to be a nostr event", http.StatusBadRequest)
		return
	}

	err = d.storage.CheckNostrEventSignature(nostrEvent)
	if err != nil {
		slog.Error(
			"d.storage.CheckNostrEventSignature(nostrEvent)",
			slog.String("error", err.Error()),
		)
		redirectBack(w, r, err.Error())
		return
	}

	pbBytes, err := hex.DecodeString(nostrEvent.PubKey)
	if err != nil {
		slog.Error(
			"hex.DecodeString(nostrEvent.PubKey)",
			slog.String("error", err.Error()),
		)
		redirectBack(w, r, err.Error())
		return
	}
	pubkey, err := schnorr.ParsePubKey(pbBytes)
	if err != nil {
		slog.Error(
			"schnorr.ParsePubKey(pbBytes)",
			slog.String("error", err.Error()),
		)
		redirectBack(w, r, err.Error())
		return
	}


	user, err := d.storage.CheckUserNpub(pubkey)
	if err != nil {
		slog.Error(
			"d.storage.CheckUserNpub(pubkey)",
			slog.String("error", err.Error()),
		)
		redirectBack(w, r, err.Error())
		return
	}

	state, err := d.storage.GetDeviceAuthorizationByUserCode(r.Context(), nostrEvent.Content)
	if err != nil {
		slog.Error(
			"d.storage.GetDeviceAuthorizationByUserCode(r.Context(), nostrEvent.Content)",
			slog.String("error", err.Error()),
		)
		redirectBack(w, r, err.Error())
		return
	}
	log.Printf("\n state: %+v", state)

	encoded, err := d.cookie.Encode(userCodeCookieName, userCodeCookie{UserCode: nostrEvent.Content, UserId: user.ID})
	if err != nil {
		slog.Error(
			"d.cookie.Encode(userCodeCookieName, userCodeCookie{nostrEvent.Content, nostrEvent.PubKey})",
			slog.String("error", err.Error()),
		)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cookie := &http.Cookie{
		Name:     userCodeCookieName,
		Value:    encoded,
		HttpOnly: true,
		Path:     "/",
	}
	http.SetCookie(w, cookie)

	// w.Header().Add("HX-Retarget", "body")
	// w.Header().Add("HX-Reswap", "innerHTML")
	templates.ConfirmDevice(nostrEvent.Content, state.ClientID, state.Scopes).Render(r.Context(), w)
}

func (d *deviceLogin) confirmHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(userCodeCookieName)
	if err != nil {
		slog.Error(
			"r.Cookie(userCodeCookieName)",
			slog.String("error", err.Error()),
		)
		redirectBack(w, r, err.Error())
		return
	}
	data := new(userCodeCookie)
	if err = d.cookie.Decode(userCodeCookieName, cookie.Value, &data); err != nil {
		slog.Error(
			"d.cookie.Decode(userCodeCookieName, cookie.Value, &data)",
			slog.String("error", err.Error()),
		)
		redirectBack(w, r, err.Error())
		return
	}
	if err = r.ParseForm(); err != nil {
		slog.Error(
			"r.ParseForm()",
			slog.String("error", err.Error()),
		)
		redirectBack(w, r, err.Error())
		return
	}

	action := r.Form.Get("action")

	switch action {
	case "allowed":
		err = d.storage.CompleteDeviceAuthorization(r.Context(), data.UserCode, data.UserId)
	case "denied":
		err = d.storage.DenyDeviceAuthorization(r.Context(), data.UserCode)
	default:
		err = errors.New("action must be one of \"allow\" or \"deny\"")
	}
	if err != nil {
		slog.Error(
			"action parsing",
			slog.String("error", err.Error()),
		)
		redirectBack(w, r, err.Error())
		return
	}

	fmt.Fprintf(w, "Device authorization %s. You can now return to the device", action)
}
