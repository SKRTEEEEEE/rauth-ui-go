package oauth

import (
	"testing"

	"rauth/models"

	"github.com/stretchr/testify/require"
)

type fakeProvider struct{}

func (f fakeProvider) BuildAuthURL(state, redirectURI string) string {
	return "https://fake.example/authorize?state=" + state + "&redirect_uri=" + redirectURI
}

func (f fakeProvider) ExchangeCode(code, redirectURI string) (string, string, error) {
	return "fake-access-token-" + code, "fake-refresh-token", nil
}

func (f fakeProvider) GetUserInfo(accessToken string) (*models.OAuthUserInfo, error) {
	return &models.OAuthUserInfo{
		ProviderUserID: accessToken,
		Email:          "fake@example.com",
		Name:           "Fake User",
	}, nil
}

func TestRegisterAndGetProvider(t *testing.T) {
	RegisterProvider("test-provider", fakeProvider{})
	provider, ok := GetProvider("test-provider")
	require.True(t, ok)
	require.IsType(t, fakeProvider{}, provider)
}

func TestGetProviderUnknown(t *testing.T) {
	_, ok := GetProvider("unknown-provider")
	require.False(t, ok)
}
