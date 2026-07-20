package server

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/go-oidfed/lib"
	"github.com/go-oidfed/lib/jwx"
	"github.com/gofiber/fiber/v2"

	"github.com/go-oidfed/offa/internal"
	"github.com/go-oidfed/offa/internal/config"
	log "github.com/go-oidfed/offa/internal/logger"
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
	if tps := config.Get().Server.TrustedProxies; len(tps) > 0 {
		serverConfig.TrustedProxies = config.Get().Server.TrustedProxies
		serverConfig.EnableTrustedProxyCheck = true
	}
	serverConfig.ProxyHeader = config.Get().Server.ForwardedIPHeader
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
			TokenEndpointAuthSigningAlg: config.Get().Signing.OIDC.DefaultAlg,
			TokenEndpointAuthSigningAlgValuesSupported: jwx.SupportedAlgsStrings(),
			UserinfoSignedResponseAlg:                  config.Get().Signing.OIDC.DefaultAlg,
			UserinfoSigningAlgValuesSupported:          jwx.SupportedAlgsStrings(),
			IDTokenSignedResponseAlg:                   config.Get().Signing.OIDC.DefaultAlg,
			IDTokenSigningAlgValuesSupported:           jwx.SupportedAlgsStrings(),
			RequestObjectSigningAlgValuesSupported:     jwx.SupportedAlgsStrings(),
			InitiateLoginURI:                           fullLoginPath,
			SoftwareID:                                 version.SOFTWAREID,
			SoftwareVersion:                            version.VERSION,
			ClientRegistrationTypes:                    fedConfig.ClientRegistrationTypes,
			Extra:                                      fedConfig.ExtraRPMetadata,
			DisplayName:                                fedConfig.DisplayName,
			Description:                                fedConfig.Description,
			Keywords:                                   fedConfig.Keywords,
			InformationURI:                             fedConfig.InformationURI,
			OrganizationName:                           fedConfig.OrganizationName,
			OrganizationURI:                            fedConfig.OrganizationURI,
		},
	}
	if fedConfig.ExtraFEMetadata != nil && len(fedConfig.ExtraFEMetadata) > 0 {
		metadata.FederationEntity = applyExtraFEMetadata(fedConfig.ExtraFEMetadata)
	}
	if metadata.RelyingParty.Extra == nil {
		metadata.RelyingParty.Extra = make(map[string]any)
	}

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
	federationLeafEntity.TrustAnchors = fedConfig.TrustAnchors
	federationLeafEntity.FederationEntity = oidfed.DynamicFederationEntity{
		ID: federationLeafEntity.EntityID(),
		Metadata: func() (*oidfed.Metadata, error) {
			jwks, err := internal.OIDCSigner().JWKS()
			if err != nil {
				return nil, err
			}
			metadata.RelyingParty.JWKS = &jwks
			return metadata, nil
		},
		AuthorityHints: func() ([]string, error) {
			return fedConfig.AuthorityHints, nil
		},
		TrustAnchorHints: func() ([]string, error) { return fedConfig.TrustAnchors.EntityIDs(), nil },
		ConfigurationLifetime: func() (time.Duration, error) {
			return fedConfig.ConfigurationLifetime.Duration(), nil
		},
		EntityStatementSigner: func() (*jwx.EntityStatementSigner, error) {
			return jwx.NewEntityStatementSigner(internal.FederationSigner()), nil
		},
		TrustMarks: func() ([]*oidfed.EntityConfigurationTrustMarkConfig, error) {
			return fedConfig.TrustMarks, nil
		},
		Extra: func() (map[string]any, []string, error) {
			return fedConfig.ExtraEntityConfigurationData, nil, nil
		},
		ShouldApplyInformationalClaims: func() (bool, error) {
			return config.Get().Federation.PublishInformationalClaimsInFederationEntity, nil
		},
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

func applyExtraFEMetadata(extraFE map[string]any) *oidfed.FederationEntityMetadata {
	fe := &oidfed.FederationEntityMetadata{}
	v := reflect.ValueOf(fe).Elem()
	t := v.Type()

	jsonTagToField := make(map[string]string)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		jsonTag := field.Tag.Get("json")
		if jsonTag != "" && jsonTag != "-" {
			if idx := strings.Index(jsonTag, ","); idx != -1 {
				jsonTag = jsonTag[:idx]
			}
			jsonTagToField[jsonTag] = field.Name
		}
	}

	for key, value := range extraFE {
		if fieldName, ok := jsonTagToField[key]; ok {
			field := v.FieldByName(fieldName)
			if field.IsValid() && field.CanSet() {
				switch field.Kind() {
				case reflect.String:
					if strVal, ok := value.(string); ok {
						field.SetString(strVal)
					}
				case reflect.Slice:
					if sliceVal, ok := value.([]interface{}); ok {
						strSlice := make([]string, len(sliceVal))
						for i, v := range sliceVal {
							if str, ok := v.(string); ok {
								strSlice[i] = str
							}
						}
						field.Set(reflect.ValueOf(strSlice))
					}
				}
			}
		}
	}

	return fe
}
