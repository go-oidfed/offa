package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-oidfed/lib"
	"github.com/go-oidfed/lib/jwx"
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/go-oidfed/offa/internal"
	"github.com/go-oidfed/offa/internal/config"
	"github.com/go-oidfed/offa/internal/version"
)

var server *fiber.App

var serverConfig = fiber.Config{
	ReadTimeout:    3 * time.Second,
	WriteTimeout:   3 * time.Second,
	IdleTimeout:    150 * time.Second,
	ReadBufferSize: 8192,
	// WriteBufferSize: 4096,
	ErrorHandler: handleError,
	Network:      "tcp",
}

var federationLeafEntity *oidfed.FederationLeaf
var scopes string
var redirectURI string
var fullLoginPath string
var fullAuthPath string

// Init initializes the server
func Init() {
	scheduleBuildOPOptions()
	initHtmls()
	initFederationEntity()
	server = fiber.New(serverConfig)
	addMiddlewares(server)
	addFederationEndpoints(server)
	addAuthHandlers(server)
	addLoginHandlers(server)
	addUserPageHandler(server)
}

func initFederationEntity() {
	fedConfig := config.Get().Federation
	if fedConfig.EntityID[len(fedConfig.EntityID)-1] == '/' {
		redirectURI = fedConfig.EntityID + "redirect"
	} else {
		redirectURI = fedConfig.EntityID + "/redirect"
	}
	fullLoginPath = fedConfig.EntityID + getFullPath(config.Get().Server.Paths.Login)
	fullAuthPath = fedConfig.EntityID + getFullPath(config.Get().Server.Paths.ForwardAuth)
	scopes = strings.Join(fedConfig.Scopes, " ")
	if scopes == "" {
		scopes = "openid profile email"
	}

	metadata := &oidfed.Metadata{
		RelyingParty: &oidfed.OpenIDRelyingPartyMetadata{
			Scope:                       scopes,
			RedirectURIS:                []string{redirectURI},
			ResponseTypes:               []string{"code"},
			GrantTypes:                  []string{"authorization_code"},
			ApplicationType:             "web",
			Contacts:                    fedConfig.Contacts,
			ClientName:                  fedConfig.ClientName,
			LogoURI:                     fedConfig.LogoURI,
			ClientURI:                   fedConfig.ClientURI,
			PolicyURI:                   fedConfig.PolicyURI,
			TOSURI:                      fedConfig.TOSURI,
			TokenEndpointAuthMethod:     "private_key_jwt",
			TokenEndpointAuthSigningAlg: config.Get().Signing.OIDC.DefaultAlgorithm,
			UserinfoSignedResponseAlg:   config.Get().Signing.OIDC.DefaultAlgorithm,
			IDTokenSignedResponseAlg:    config.Get().Signing.OIDC.DefaultAlgorithm,
			InitiateLoginURI:            fullLoginPath,
			SoftwareID:                  version.SOFTWAREID,
			SoftwareVersion:             version.VERSION,
			ClientRegistrationTypes:     []string{"automatic"},
			Extra:                       fedConfig.ExtraRPMetadata,
			DisplayName:                 fedConfig.DisplayName,
			Description:                 fedConfig.Description,
			Keywords:                    fedConfig.Keywords,
			InformationURI:              fedConfig.InformationURI,
			OrganizationName:            fedConfig.OrganizationName,
			OrganizationURI:             fedConfig.OrganizationURI,
		},
	}
	if metadata.RelyingParty.Extra == nil {
		metadata.RelyingParty.Extra = make(map[string]any)
	}
	metadata.RelyingParty.Extra["id_token_signing_alg_values_supported"] = jwx.SupportedAlgsStrings()
	metadata.RelyingParty.Extra["userinfo_signing_alg_values_supported"] = jwx.SupportedAlgsStrings()
	metadata.RelyingParty.Extra["request_object_alg_values_supported"] = jwx.SupportedAlgsStrings()
	metadata.RelyingParty.Extra["token_endpoint_auth_signing_alg_values_supported"] = jwx.SupportedAlgsStrings()

	if fedConfig.ExtraEntityConfigurationData == nil {
		fedConfig.ExtraEntityConfigurationData = make(map[string]any)
	}
	fedConfig.ExtraEntityConfigurationData["offa_version"] = version.VERSION
	var err error
	federationLeafEntity, err = oidfed.NewFederationLeaf(
		fedConfig.EntityID, fedConfig.AuthorityHints, fedConfig.TrustAnchors, metadata,
		jwx.NewEntityStatementSigner(
			internal.FederationSigner(),
		), fedConfig.ConfigurationLifetime.Duration(), internal.OIDCSigner(),
		fedConfig.ExtraEntityConfigurationData,
	)
	if err != nil {
		log.Fatal(err)
	}
	federationLeafEntity.TrustMarks = fedConfig.TrustMarks
	federationLeafEntity.MetadataUpdater = func(metadata *oidfed.Metadata) {
		jwks := internal.OIDCSigner().JWKS()
		metadata.RelyingParty.JWKS = &jwks
	}
}

func start(s *fiber.App) {
	if !config.Get().Server.TLS.Enabled {
		log.WithField("port", config.Get().Server.Port).Info("TLS is disabled starting http server")
		log.WithError(s.Listen(fmt.Sprintf("%s:%d", config.Get().Server.IPListen, config.Get().Server.Port))).Fatal()
	}
	// TLS enabled
	if config.Get().Server.TLS.RedirectHTTP {
		httpServer := fiber.New(serverConfig)
		httpServer.All(
			"*", func(ctx *fiber.Ctx) error {
				//goland:noinspection HttpUrlsUsage
				return ctx.Redirect(
					strings.Replace(ctx.Request().URI().String(), "http://", "https://", 1),
					fiber.StatusPermanentRedirect,
				)
			},
		)
		log.Info("TLS and http redirect enabled, starting redirect server on port 80")
		go func() {
			log.WithError(httpServer.Listen(config.Get().Server.IPListen + ":80")).Fatal()
		}()
	}
	time.Sleep(time.Millisecond) // This is just for a more pretty output with the tls header printed after the http one
	log.Info("TLS enabled, starting https server on port 443")
	log.WithError(
		s.ListenTLS(
			config.Get().Server.IPListen+":443", config.Get().Server.TLS.Cert, config.Get().Server.TLS.Key,
		),
	).Fatal()
}

// Start starts the server
func Start() {
	start(server)
}

func getFullPath(path string) string {
	if len(path) == 0 {
		return config.Get().Server.Basepath
	}
	if path[0] != '/' {
		path = "/" + path
	}
	return config.Get().Server.Basepath + path
}
