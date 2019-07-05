package main

import (
  "context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
  "time"

  "github.com/DeviaVir/dexter/utils"
	"github.com/coreos/go-oidc"
	"github.com/ghodss/yaml"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
  "golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	"gopkg.in/square/go-jose.v2/jwt"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	clientCmdApi "k8s.io/client-go/tools/clientcmd/api"
	clientCmdLatest "k8s.io/client-go/tools/clientcmd/api/latest"
)

// dexterOIDC: struct to store the required data and provide methods to
// authenticate with Googles OpenID implementation
type dexterOIDChttp struct {
	url             string            // URL to listen for
	callback        string            // URL to listen for callbacks
	endpoint        string            // azure or google
	azureTenant     string            // azure tenant
	clientID        string            // clientID commandline flag
	clientSecret    string            // clientSecret commandline flag
	authName        string            // Cluster name
  state           string            // CSRF protection
	scopes          []string          // Additional scopes to request
	authCodeOptions map[string]string // Authorization code options
	certificateFile string            // SSL certificate file
	keyFile         string            // SSL private key file
	Oauth2Config    *oauth2.Config    // oauth2 configuration
	httpClient      *http.Client      // http client
	httpServer      http.Server       // http server
}

// setup and populate the OAuth2 config
func (d *dexterOIDChttp) createOauth2Config() error {
	// setup oidc client context
	ctx := oidc.ClientContext(context.Background(), d.httpClient)

	// populate oauth2 config
	d.Oauth2Config.ClientID = oidcDataHTTP.clientID
	d.Oauth2Config.ClientSecret = oidcDataHTTP.clientSecret
	d.Oauth2Config.RedirectURL = oidcDataHTTP.callback

	switch oidcDataHTTP.endpoint {
	case "azure":
		d.Oauth2Config.Endpoint = microsoft.AzureADEndpoint(oidcDataHTTP.azureTenant)
		d.Oauth2Config.Scopes = []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "email"}
	case "google":
		d.Oauth2Config.Endpoint = google.Endpoint
		d.Oauth2Config.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	default:
		// Attempt to use endpoint as generic issuer if it is a valid URL
		_, err := url.Parse(oidcDataHTTP.endpoint)
		if err != nil {
			return fmt.Errorf("unsupported endpoint: %s", oidcDataHTTP.endpoint)
		}

		// Attempt to gather endpoint information via discovery
		genericProvider, err := oidc.NewProvider(ctx, oidcDataHTTP.endpoint)
		if err != nil {
			return err
		}

		d.Oauth2Config.Endpoint = genericProvider.Endpoint()
		d.Oauth2Config.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	// Append additional specified scopes
	d.Oauth2Config.Scopes = append(d.Oauth2Config.Scopes, d.scopes...)

	return nil
}

func (d *dexterOIDChttp) handler(w http.ResponseWriter, r *http.Request) {
  http.Redirect(w, r, d.authURL(), http.StatusSeeOther)
}


func (d *dexterOIDChttp) authURL() string {
	// Use provided authorization code options
	options := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
	}

	for optionKey, optionValue := range d.authCodeOptions {
		options = append(options, oauth2.SetAuthURLParam(optionKey, optionValue))
	}

	return d.Oauth2Config.AuthCodeURL(d.state, options...)
}

func (d *dexterOIDChttp) callbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Info("callback received")

	// Get code and state from the passed form value
	code := r.FormValue("code")
	callbackState := r.FormValue("state")

	// verify code AND state are defined
	if code == "" || callbackState == "" {
		log.Errorf("no code or state in request: %q", r.Form)
		http.Error(w, "no code or state found in your request", http.StatusBadRequest)
		return
	}

	// compare callback state and initial state
	if callbackState != oidcDataHTTP.state {
		log.Error("state mismatch! Someone could be tampering with your connection!")
		http.Error(w, "state mismatch! Someone could be tampering with your connection!", http.StatusBadRequest)
		return
	}

	// create context and exchange authCode for token
	ctx := oidc.ClientContext(r.Context(), d.httpClient)
	token, err := oidcDataHTTP.Oauth2Config.Exchange(ctx, code)
	if err != nil {
		log.Errorf("Failed to exchange auth code: %s", err)
		http.Error(w, "Failed to exchange auth code!", http.StatusInternalServerError)
		return
	}

	log.Info("exchanged authCode for JWT token. Refresh token was supplied")

	if err := d.showK8sConfig(w, token); err != nil {
		log.Errorf("Failed to write k8s config: %s", err)
		http.Error(w, fmt.Sprintf("Failed to write k8s config: %s", err), http.StatusInternalServerError)
		return
	}

	return
}

type customClaim struct {
	Email string `json:"email"`
}

// show the k8s config
func (d *dexterOIDChttp) showK8sConfig(w http.ResponseWriter, token *oauth2.Token) error {
	idToken := token.Extra("id_token").(string)

	parsed, err := jwt.ParseSigned(idToken)
	if err != nil {
		return fmt.Errorf("Failed to parse token: %s", err)
	}

	customClaim := &customClaim{}
	claims := &jwt.Claims{}

	err = parsed.UnsafeClaimsWithoutVerification(claims, customClaim)

	if err != nil {
		return fmt.Errorf("failed to get user details from token: %s", err)
	}

	// Use e-mail claim if configuration wasn't discovered in kubeconfig
	authName := customClaim.Email
	if d.authName != "" {
		authName = d.authName
	}

	// construct the authinfo struct
	authInfo := &clientCmdApi.AuthInfo{
		AuthProvider: &clientCmdApi.AuthProviderConfig{
			Name: "oidc",
			Config: map[string]string{
				"client-id":      d.clientID,
				"client-secret":  d.clientSecret,
				"id-token":       idToken,
				"idp-issuer-url": claims.Issuer,
				"refresh-token":  token.RefreshToken,
			},
		},
	}

	// contruct the config snippet
	config := &clientCmdApi.Config{
		AuthInfos: map[string]*clientCmdApi.AuthInfo{authName: authInfo},
	}

	// create a JSON representation
	json, err := k8sRuntime.Encode(clientCmdLatest.Codec, config)

	if err != nil {
		return fmt.Errorf("failed to runtime encode config: %s", err)
	}

	// convert JSON to YAML
	output, err := yaml.JSONToYAML(json)

	if err != nil {
		return fmt.Errorf("failed to convert JSON to YAML: %s", err)
	}

	// show the result
	//log.Infof("Here's the config snippet that would be merged with your config: \n%v", string(output))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(output))

	return nil
}

func (d *dexterOIDChttp) main() {
	parsedURL, err := url.Parse(d.url)
	if err != nil {
		log.Errorf("Failed to parse listener URL: %s", err)
		panic(1)
	}

	http.HandleFunc("/", d.handler)
	http.HandleFunc("/callback", d.callbackHandler)
	if parsedURL.Scheme == "http" {
		err = http.ListenAndServe(parsedURL.Host, nil)
    if err != nil {
			if err != http.ErrServerClosed {
				log.Errorf("Failed to start web server: %s", err)
				panic(1)
			}
		}
	} else {
		if !strings.Contains(d.url, ":") {
			d.url = fmt.Sprintf("%s:443", d.url)
		}

		err = http.ListenAndServeTLS(d.url, d.certificateFile, d.keyFile, nil)
		if err != nil {
			if err != http.ErrServerClosed {
				log.Errorf("Failed to start web server: %s", err)
				panic(1)
			}
		}
	}
}

func (d *dexterOIDChttp) getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

var (
  oidcDataHTTP = dexterOIDChttp{
		Oauth2Config: &oauth2.Config{},
		httpClient:   &http.Client{Timeout: 2 * time.Second},
	}
)

func main() {
	// set log format & level
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	log.SetLevel(log.InfoLevel)

  oidcDataHTTP.endpoint = oidcDataHTTP.getEnv("ENDPOINT", "google")
	oidcDataHTTP.url = oidcDataHTTP.getEnv("URL", "http://0.0.0.0:3000")
	oidcDataHTTP.callback = oidcDataHTTP.getEnv("CALLBACK", "http://127.0.0.1:3000/callback")
	oidcDataHTTP.azureTenant = oidcDataHTTP.getEnv("AZURE_TENANT", "")
	oidcDataHTTP.clientID = oidcDataHTTP.getEnv("CLIENT_ID", "REDACTED")
	oidcDataHTTP.clientSecret = oidcDataHTTP.getEnv("CLIENT_SECRET", "REDACTED")
	oidcDataHTTP.authName = oidcDataHTTP.getEnv("AUTH_NAME", "kubernetes")
  oidcDataHTTP.httpClient = &http.Client{Timeout: 2 * time.Second}
  oidcDataHTTP.Oauth2Config = &oauth2.Config{}

	if oidcDataHTTP.clientID == "" || oidcDataHTTP.clientSecret == "" {
		log.Error("clientID and clientSecret cannot be empty!")
		return
	}

  oidcDataHTTP.state = utils.RandomString()

	// setup oauth2 object
	if err := oidcDataHTTP.createOauth2Config(); err != nil {
		log.Errorf("oauth2 configuration failed: %s", err)
		return
	}

	// spawn HTTP server
	oidcDataHTTP.main()
}
