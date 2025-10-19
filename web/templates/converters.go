package templates

import (
	"github.com/lescuer97/nostr-oicd/storage"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// ClientToFormData converts an op.Client interface to ClientFormData for form population.
// This works with any implementation of the op.Client interface, avoiding circular dependencies.
func ClientToFormData(client op.Client) ClientFormData {

	return ClientFormData{
		ClientID:                   client.GetID(),
		RedirectURIs:               client.RedirectURIs(),
		ApplicationType:            int(client.ApplicationType()),
		ResponseTypes:              responseTypesToStrings(client.ResponseTypes()),
		GrantTypes:                 grantTypesToStrings(client.GrantTypes()),
		AccessTokenType:            int(client.AccessTokenType()),
		PostLogoutRedirectURIGlobs: []string{}, // Not exposed via op.Client interface
		RedirectURIGlobs:           []string{}, // Not exposed via op.Client interface
	}
}

// FormDataToStorageClient converts ClientFormData to a storage.Client struct.
// This creates a new storage client with the form data, handling all necessary type conversions
// from form integers to op.ApplicationType and op.AccessTokenType enums.
//
// The function requires a secret parameter (typically a newly generated client secret for new clients,
// or the existing secret for updates). Empty slices will be preserved as empty (not nil).
//
// Usage pattern:
//
//	formData := &ClientFormData{...}
//	clientSecret := generateSecret() // or retrieve existing secret
//	storageClient := FormDataToStorageClient(formData, clientSecret)
func FormDataToStorageClient(data *ClientFormData, secret string) *storage.Client {
	if data == nil {
		return nil
	}

	// Convert integer application type to op.ApplicationType
	appType := op.ApplicationType(data.ApplicationType)

	// Convert integer access token type to op.AccessTokenType
	accessTokenType := op.AccessTokenType(data.AccessTokenType)

	// Convert response type strings to oidc.ResponseType slice
	responseTypes := StringsToResponseTypes(data.ResponseTypes)

	// Convert grant type strings to oidc.GrantType slice
	grantTypes := StringsToGrantTypes(data.GrantTypes)

	// Create and return the storage.Client using the NewClient constructor
	return storage.NewClient(
		data.ClientID,
		secret,
		data.RedirectURIs,
		appType,
		oidc.AuthMethodNone, // Default to no authentication method, can be made configurable if needed
		responseTypes,
		grantTypes,
		accessTokenType,
		data.RedirectURIGlobs,
		data.PostLogoutRedirectURIGlobs,
	)
}

// FormDataToClient converts ClientFormData to form data suitable for storage operations.
// Since op.Client is an interface with read-only methods, this returns the form data as-is.
// To persist a client, use the storage package's AddClient or UpdateClient methods directly
// with the extracted form data.
//
// Usage pattern:
//
//	formData := &ClientFormData{...}
//	// Pass formData fields to storage.AddClient() or storage.UpdateClient()
//	// The storage package handles creating/updating the internal storage.Client struct
func FormDataToClient(data *ClientFormData) ClientFormData {
	if data == nil {
		return ClientFormData{}
	}
	return *data
}

// ========== Helper Conversion Functions ==========

// ResponseTypesToStrings converts []oidc.ResponseType to []string
func ResponseTypesToStrings(responseTypes []oidc.ResponseType) []string {
	if len(responseTypes) == 0 {
		return []string{}
	}

	result := make([]string, 0, len(responseTypes))
	for _, rt := range responseTypes {
		result = append(result, string(rt))
	}
	return result
}

// StringsToResponseTypes converts []string to []oidc.ResponseType
func StringsToResponseTypes(responseTypeStrings []string) []oidc.ResponseType {
	if len(responseTypeStrings) == 0 {
		return []oidc.ResponseType{}
	}

	result := make([]oidc.ResponseType, 0, len(responseTypeStrings))
	for _, rt := range responseTypeStrings {
		result = append(result, oidc.ResponseType(rt))
	}
	return result
}

// GrantTypesToStrings converts []oidc.GrantType to []string
func GrantTypesToStrings(grantTypes []oidc.GrantType) []string {
	if len(grantTypes) == 0 {
		return []string{}
	}

	result := make([]string, 0, len(grantTypes))
	for _, gt := range grantTypes {
		result = append(result, string(gt))
	}
	return result
}

// StringsToGrantTypes converts []string to []oidc.GrantType
func StringsToGrantTypes(grantTypeStrings []string) []oidc.GrantType {
	if len(grantTypeStrings) == 0 {
		return []oidc.GrantType{}
	}

	result := make([]oidc.GrantType, 0, len(grantTypeStrings))
	for _, gt := range grantTypeStrings {
		result = append(result, oidc.GrantType(gt))
	}
	return result
}

// Keep private versions for internal use
func responseTypesToStrings(responseTypes []oidc.ResponseType) []string {
	return ResponseTypesToStrings(responseTypes)
}

func stringsToResponseTypes(responseTypeStrings []string) []oidc.ResponseType {
	return StringsToResponseTypes(responseTypeStrings)
}

func grantTypesToStrings(grantTypes []oidc.GrantType) []string {
	return GrantTypesToStrings(grantTypes)
}

func stringsToGrantTypes(grantTypeStrings []string) []oidc.GrantType {
	return StringsToGrantTypes(grantTypeStrings)
}

// ========== Optional: Application Type and Access Token Type Converters ==========

// applicationTypeToString converts op.ApplicationType to string
func applicationTypeToString(at op.ApplicationType) string {
	return at.String()
}

// stringToApplicationType converts string to op.ApplicationType
func stringToApplicationType(s string) op.ApplicationType {
	appType, _ := op.ApplicationTypeString(s)
	return appType
}

// accessTokenTypeToString converts op.AccessTokenType to string
func accessTokenTypeToString(att op.AccessTokenType) string {
	return att.String()
}

// stringToAccessTokenType converts string to op.AccessTokenType
func stringToAccessTokenType(s string) op.AccessTokenType {
	tokenType, _ := op.AccessTokenTypeString(s)
	return tokenType
}
