// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package providers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"time"

	"github.com/openpubkey/openpubkey/discover"
	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	oidchttp "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func nonceFormAuthorization(nonce string) oidchttp.FormAuthorization {
	return func(values url.Values) {
		values.Set("nonce", nonce)
	}
}

func GetDefaultDeviceFlowOpOptions(issuer string, clientID string) *StandardOpOptions {
	return &StandardOpOptions{
		Issuer:         issuer,
		ClientID:       clientID,
		Scopes:         []string{"openid profile email"},
		PromptType:     "consent",
		AccessType:     "offline",
		RedirectURIs:   []string{},
		GQSign:         false,
		OpenBrowser:    true,
		HttpClient:     nil,
		IssuedAtOffset: 1 * time.Minute,
	}
}

// NewDeviceFlowOpWithOptions creates a device-flow OP with configuration specified
// using an options struct. This is useful if you want to use your own OIDC
// Client or override the configuration.
func NewDeviceFlowOpWithOptions(opts *StandardOpOptions) BrowserOpenIdProvider {
	return &DeviceFlowOp{
		StandardOp: StandardOp{
			clientID:                  opts.ClientID,
			ClientSecret:              opts.ClientSecret,
			Scopes:                    opts.Scopes,
			PromptType:                opts.PromptType,
			AccessType:                opts.AccessType,
			RedirectURIs:              opts.RedirectURIs,
			GQSign:                    opts.GQSign,
			OpenBrowser:               opts.OpenBrowser,
			HttpClient:                opts.HttpClient,
			IssuedAtOffset:            opts.IssuedAtOffset,
			issuer:                    opts.Issuer,
			requestTokensOverrideFunc: nil,
			publicKeyFinder: discover.PublicKeyFinder{
				JwksFunc: func(ctx context.Context, issuer string) ([]byte, error) {
					return discover.GetJwksByIssuer(ctx, issuer, opts.HttpClient)
				},
			},
		},
	}
}

type DeviceFlowOp struct {
	StandardOp
}

type DeviceFlowRefreshable struct {
	DeviceFlowOp
}

var _ OpenIdProvider = (*DeviceFlowOp)(nil)
var _ BrowserOpenIdProvider = (*DeviceFlowOp)(nil)
var _ RefreshableOpenIdProvider = (*DeviceFlowRefreshable)(nil)

// NewDeviceFLowOp creates a standard OP (OpenID Provider) using the
// default configuration options and returns a BrowserOpenIdProvider.
func NewDeviceFLowOp(issuer string, clientID string) BrowserOpenIdProvider {
	options := GetDefaultStandardOpOptions(issuer, clientID)
	return NewStandardOpWithOptions(options)
}

func (s *DeviceFlowOp) requestTokens(ctx context.Context, cicHash string) (*simpleoidc.Tokens, error) {
	if s.requestTokensOverrideFunc != nil {
		return s.requestTokensOverrideFunc(cicHash)
	}

	cookieHandler, err := configCookieHandler()
	if err != nil {
		return nil, err
	}

	// authelia does not work with device flow and nonce
	// is this for all device flows true?
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithSigningAlgsFromDiscovery(),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(s.IssuedAtOffset),
			rp.WithNonce(func(ctx context.Context) string { return cicHash }),
		),
	}

	options = append(options, rp.WithPKCE(cookieHandler))
	if s.HttpClient != nil {
		options = append(options, rp.WithHTTPClient(s.HttpClient))
	}

	relyingParty, err := rp.NewRelyingPartyOIDC(
		ctx,
		s.issuer,
		s.clientID,
		s.ClientSecret,
		"",
		s.Scopes,
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating provider: %w", err)
	}

	dar, err := rp.DeviceAuthorization(ctx, s.Scopes, relyingParty, nonceFormAuthorization(cicHash))
	if err != nil {
		return nil, err
	}

	qrCodeURL := dar.VerificationURI
	if dar.VerificationURIComplete != "" {
		qrCodeURL = dar.VerificationURIComplete
	}

	code, err := createQRCode(qrCodeURL)
	if err != nil {
		// do not fail, just log the error
		logrus.Warnf("could no create qrcode, fallback to textual representation only: %s", err)
	} else {
		logrus.Infof("\n%s\n", code)
	}

	textual := strings.Builder{}

	if code != "" {
		textual.WriteString("Scan the QR code or, using a browser visit:\n\n ")
	} else {
		textual.WriteString("Using a browser visit:\n\n ")
	}

	textual.WriteString(dar.VerificationURI)
	textual.WriteString("\n\nAnd enter the code:\n\n ")
	textual.WriteString(dar.UserCode)

	textual.WriteString("\n\nComplete URL:\n\n ")
	textual.WriteString(qrCodeURL)
	textual.WriteString("\n\nHint: in most terminals ctrl-click/click on the URLs opens them in a browser.")
	textual.WriteString("\n\n")

	logrus.Info(textual.String())

	interval := 3 * time.Second
	if dar.Interval > 0 {
		interval = time.Duration(dar.Interval) * time.Second
	}

	atr, err := rp.DeviceAccessToken(ctx, dar.DeviceCode, interval, relyingParty)
	if err != nil {
		return nil, err
	}

	// TODO: do we need to handle the refresh token case? link in standard op?

	return &simpleoidc.Tokens{
		IDToken:      []byte(atr.IDToken),
		RefreshToken: []byte(atr.RefreshToken),
		AccessToken:  []byte(atr.AccessToken)}, nil
}

func (s *DeviceFlowOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error) {
	// Define our commitment as the hash of the client instance claims
	cicHash, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error calculating client instance claim commitment: %w", err)
	}
	tokens, err := s.requestTokens(ctx, string(cicHash))
	if err != nil {
		return nil, err
	}
	if s.GQSign {
		idToken := tokens.IDToken
		if gqToken, err := CreateGQToken(ctx, idToken, s); err != nil {
			return nil, err
		} else {
			tokens.IDToken = gqToken
			return tokens, nil
		}
	}
	return tokens, nil
}

func (s DeviceFlowRefreshable) RefreshTokens(ctx context.Context, refreshToken []byte) (*simpleoidc.Tokens, error) {
	cookieHandler, err := configCookieHandler()
	if err != nil {
		return nil, err
	}
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(s.IssuedAtOffset),
			rp.WithNonce(nil), // disable nonce check
		),
	}
	options = append(options, rp.WithPKCE(cookieHandler))
	if s.HttpClient != nil {
		options = append(options, rp.WithHTTPClient(s.HttpClient))
	}

	// The redirect URI is not sent in the refresh request so we set it to an empty string.
	// According to the OIDC spec the only values send on a refresh request are:
	// client_id, client_secret, grant_type, refresh_token, and scope.
	// https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
	redirectURI := ""
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, s.issuer, s.clientID,
		s.ClientSecret, redirectURI, s.Scopes, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create RP to verify token: %w", err)
	}
	retTokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relyingParty, string(refreshToken), "", "")
	if err != nil {
		return nil, err
	}

	if retTokens.RefreshToken == "" {
		// Google does not rotate refresh tokens, the one you get at the
		// beginning is the only one you'll ever get. This may not be true
		// of OPs.
		retTokens.RefreshToken = string(refreshToken)
	}

	return &simpleoidc.Tokens{
		IDToken:      []byte(retTokens.IDToken),
		RefreshToken: []byte(retTokens.RefreshToken),
		AccessToken:  []byte(retTokens.AccessToken)}, nil
}

func (s *DeviceFlowOp) PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error) {
	return s.publicKeyFinder.ByToken(ctx, s.issuer, token)
}

func (s *DeviceFlowOp) PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error) {
	return s.StandardOp.PublicKeyByKeyId(ctx, keyID)
}

func (s *DeviceFlowOp) Issuer() string {
	return s.StandardOp.Issuer()
}

func (s *DeviceFlowOp) ClientID() string {
	return s.StandardOp.ClientID()
}

func (s *DeviceFlowOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	vp := NewProviderVerifier(
		s.issuer,
		ProviderVerifierOpts{
			CommitType:        CommitTypesEnum.NONCE_CLAIM,
			ClientID:          s.clientID,
			DiscoverPublicKey: &s.publicKeyFinder,
		})
	return vp.VerifyIDToken(ctx, idt, cic)
}

func (s *DeviceFlowOp) VerifyRefreshedIDToken(ctx context.Context, origIdt []byte, reIdt []byte) error {
	if err := simpleoidc.SameIdentity(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token is for different subject than original ID Token: %w", err)
	}
	if err := simpleoidc.RequireOlder(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token should not be issued before original ID Token: %w", err)
	}

	options := []rp.Option{}
	if s.HttpClient != nil {
		options = append(options, rp.WithHTTPClient(s.HttpClient))
	}
	redirectURI := ""
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, s.issuer, s.clientID,
		s.ClientSecret, redirectURI, s.Scopes, options...)
	if err != nil {
		return fmt.Errorf("failed to create RP to verify token: %w", err)
	}
	_, err = rp.VerifyIDToken[*oidc.IDTokenClaims](ctx, string(reIdt), relyingParty.IDTokenVerifier())
	return err
}

// HookHTTPSession provides a means to hook the HTTP Server session resulting
// from the OpenID Provider sending an authcode to the OIDC client by
// redirecting the user's browser with the authcode supplied in the URI.
// If this hook is set, it will be called after the receiving the authcode
// but before send an HTTP response to the user. The code which sets this hook
// can choose what HTTP response to server to the user.
//
// We use this so that we can redirect the user web browser window to
// the MFA Cosigner URI after the user finishes the OIDC Auth flow. This
// method is only available to browser based providers.
func (s *DeviceFlowOp) HookHTTPSession(h http.HandlerFunc) {
	s.StandardOp.HookHTTPSession(h)
}

// ReuseBrowserWindowHook is needed so that do not open more than one browser window.
// If we are using a web based OpenID Provider chooser, we have already opened one
// window on the user's browser. We should reuse that window here rather than
// opening a second browser window.
func (s *DeviceFlowOp) ReuseBrowserWindowHook(h chan string) {
	s.StandardOp.ReuseBrowserWindowHook(h)
}

// TriggerBrowserWindowHook ris used by testing to trigger the redirect without
// calling out the OP. This is hidden by not including in the interface.
func (s *DeviceFlowOp) TriggerBrowserWindowHook(uri string) {
	s.StandardOp.TriggerBrowserWindowHook(uri)
}
