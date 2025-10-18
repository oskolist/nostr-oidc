package templates

import (
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

// responseTypesToStrings converts []oidc.ResponseType to []string
func responseTypesToStrings(responseTypes []oidc.ResponseType) []string {
	if len(responseTypes) == 0 {
		return []string{}
	}

	result := make([]string, 0, len(responseTypes))
	for _, rt := range responseTypes {
		result = append(result, string(rt))
	}
	return result
}

// stringsToResponseTypes converts []string to []oidc.ResponseType
func stringsToResponseTypes(responseTypeStrings []string) []oidc.ResponseType {
	if len(responseTypeStrings) == 0 {
		return []oidc.ResponseType{}
	}

	result := make([]oidc.ResponseType, 0, len(responseTypeStrings))
	for _, rt := range responseTypeStrings {
		result = append(result, oidc.ResponseType(rt))
	}
	return result
}

// grantTypesToStrings converts []oidc.GrantType to []string
func grantTypesToStrings(grantTypes []oidc.GrantType) []string {
	if len(grantTypes) == 0 {
		return []string{}
	}

	result := make([]string, 0, len(grantTypes))
	for _, gt := range grantTypes {
		result = append(result, string(gt))
	}
	return result
}

// stringsToGrantTypes converts []string to []oidc.GrantType
func stringsToGrantTypes(grantTypeStrings []string) []oidc.GrantType {
	if len(grantTypeStrings) == 0 {
		return []oidc.GrantType{}
	}

	result := make([]oidc.GrantType, 0, len(grantTypeStrings))
	for _, gt := range grantTypeStrings {
		result = append(result, oidc.GrantType(gt))
	}
	return result
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
