package server

import (
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-oidfed/lib"
	"github.com/go-oidfed/lib/apimodel"
	"github.com/go-oidfed/lib/oidfedconst"
	"github.com/gofiber/fiber/v2"
	"github.com/zachmann/go-utils/ctxutils"

	"github.com/go-oidfed/offa/internal/config"
	log "github.com/go-oidfed/offa/internal/logger"
)

type postLoginRequest struct {
	Issuer        string `json:"iss" form:"iss" query:"iss"`
	LoginHint     string `json:"login_hint" form:"login_hint" query:"login_hint"`
	TargetLinkURI string `json:"target_link_uri" form:"target_link_uri" query:"target_link_uri"`
}

func addLoginHandlers(s fiber.Router) {
	path := config.Get().Server.Paths.Login
	s.Get(
		path, func(c *fiber.Ctx) error {
			opID := ctxutils.FirstNonEmptyQueryParameter(c, "iss", "op", "entity_id", "entity", "issuer")
			if opID != "" {
				next := ctxutils.FirstNonEmptyQueryParameter(c, "target_link_uri", "next")
				return doLogin(c, opID, next, c.Query("login_hint"))
			}
			return showLoginPage(c)
		},
	)
	s.Post(
		path, func(c *fiber.Ctx) error {
			var req postLoginRequest
			if err := c.BodyParser(&req); err != nil {
				return c.JSON(oidfed.ErrorInvalidRequest("could not parse request parameters: " + err.Error()))
			}
			return doLogin(c, req.Issuer, req.TargetLinkURI, req.LoginHint)
		},
	)
	s.Get("/redirect", codeExchange)
}

type externalButton struct {
	Href      string
	Text      string
	HTMLClass string
	CustomCSS string
}

func showLoginPage(c *fiber.Ctx) error {
	next := c.Query("next", config.Get().Federation.EntityID)
	return render(
		c, "login", map[string]any{
			"client_name":      config.Get().Federation.ClientName,
			"logo_uri":         config.Get().Federation.LogoURI,
			"login-path":       config.Get().Server.Paths.Login,
			"login-url":        fullLoginPath,
			"entity-id":        config.Get().Federation.EntityID,
			"ops":              getOPOptions(),
			"next":             next,
			"external-buttons": buildExternalButtons(next),
			"conf":             config.Get().OPDiscovery,
		},
	)
}

func buildExternalButtons(next string) []externalButton {
	ext := config.Get().OPDiscovery.External
	if !ext.Enabled {
		return nil
	}
	entityID := config.Get().Federation.EntityID
	buttons := make([]externalButton, 0, len(ext.Services))
	for _, svc := range ext.Services {
		u, err := url.Parse(svc.URL)
		if err != nil {
			log.WithError(err).Error("skipping external discovery service with unparseable url")
			continue
		}
		q := u.Query()
		q.Set("target_link_uri", next)
		if svc.IncludeEntityID {
			q.Set("entity_id", entityID)
		}
		u.RawQuery = q.Encode()
		buttons = append(
			buttons, externalButton{
				Href:      u.String(),
				Text:      svc.Button.Text,
				HTMLClass: svc.Button.HTMLClass,
				CustomCSS: svc.Button.CustomCSS,
			},
		)
	}
	return buttons
}

type opOption struct {
	EntityID    string
	DisplayName string
	KeyWords    string
	LogoURI     string
}

var (
	opOptions   []opOption
	opOptionsMu sync.RWMutex
)

func scheduleBuildOPOptions() {
	conf := config.Get().OPDiscovery.Local
	if !conf.Enabled {
		return
	}
	ticker := time.NewTicker(conf.EntityCollectionInterval.Duration())

	// Collect entity options in the background instead of synchronously: an
	// unreachable or slow trust anchor would otherwise block server startup.
	// The first run starts immediately (concurrently with the HTTP server
	// bind) rather than waiting for the first ticker tick, so the login page
	// gets populated as soon as the data is available.
	go buildOPOptions()

	go func() {
		for range ticker.C {
			buildOPOptions()
		}
	}()
}

func buildOPOptions() {
	filters := []oidfed.EntityCollectionFilter{}
	if tms := config.Get().Federation.RequiredOPTrustMarks; len(tms) > 0 {
		filters = append(
			filters, oidfed.NewEntityCollectionFilter(
				func(e *oidfed.CollectedEntity) bool {
					ok, err := oidfed.VerifyEntityHasValidTrustmarks(
						e.EntityID, tms, config.Get().Federation.TrustAnchors,
					)
					if err != nil {
						log.WithError(err).Error("error during trustmark verification")
					}
					return ok
				},
			),
		)
	}
	allOPs := make(map[string]*oidfed.CollectedEntity)
	var options []opOption
	var collector oidfed.EntityCollector
	if config.Get().OPDiscovery.Local.UseEntityCollectionEndpoint {
		collector = oidfed.SmartRemoteEntityCollector{TrustAnchors: config.Get().Federation.TrustAnchors.EntityIDs()}
	} else {
		collector = &oidfed.SimpleEntityCollector{}
	}
	for _, ta := range config.Get().Federation.TrustAnchors {
		ops, _ := oidfed.FilterableVerifiedChainsEntityCollector{
			Collector: collector,
			Filters:   filters,
		}.CollectEntities(
			apimodel.EntityCollectionRequest{
				TrustAnchor: ta.EntityID,
				EntityTypes: []string{oidfedconst.EntityTypeOpenIDProvider},
			},
		)
		if ops != nil {
			for _, op := range ops.Entities {
				allOPs[op.EntityID] = op
			}
		}
	}
	for _, op := range allOPs {
		options = append(
			options, opOption{
				EntityID:    op.EntityID,
				DisplayName: getDisplayNameFromEntityInfo(op),
				LogoURI:     getLogoURIFromEntityInfo(op),
				KeyWords:    strings.Join(getKeywordsFromEntityInfo(op), " "),
			},
		)
	}
	opOptionsMu.Lock()
	opOptions = options
	opOptionsMu.Unlock()
}

// getOPOptions returns a snapshot of the currently collected OP options. It is
// used by request handlers; collection runs in the background, so the slice
// must be read under the lock to avoid a data race with buildOPOptions.
func getOPOptions() []opOption {
	opOptionsMu.RLock()
	defer opOptionsMu.RUnlock()
	return opOptions
}

func getDisplayNameFromEntityInfo(entity *oidfed.CollectedEntity) string {
	if entity == nil {
		return ""
	}
	if entity.UIInfos == nil {
		return entity.EntityID
	}
	op, ok := entity.UIInfos[oidfedconst.EntityTypeOpenIDProvider]
	if ok && op.DisplayName != "" {
		return op.DisplayName
	}
	fed, ok := entity.UIInfos[oidfedconst.EntityTypeFederationEntity]
	if ok && fed.DisplayName != "" {
		return fed.DisplayName
	}
	return entity.EntityID
}

func getKeywordsFromEntityInfo(entity *oidfed.CollectedEntity) []string {
	if entity == nil || entity.UIInfos == nil {
		return nil
	}
	op, ok := entity.UIInfos[oidfedconst.EntityTypeOpenIDProvider]
	if ok && op.Keywords != nil {
		return op.Keywords
	}
	fed, ok := entity.UIInfos[oidfedconst.EntityTypeFederationEntity]
	if ok && fed.Keywords != nil {
		return fed.Keywords
	}
	return nil
}

func getLogoURIFromEntityInfo(entity *oidfed.CollectedEntity) string {
	if entity == nil || entity.UIInfos == nil {
		return ""
	}
	op, ok := entity.UIInfos[oidfedconst.EntityTypeOpenIDProvider]
	if ok && op.LogoURI != "" {
		return op.LogoURI
	}
	fed, ok := entity.UIInfos[oidfedconst.EntityTypeFederationEntity]
	if ok && fed.LogoURI != "" {
		return fed.LogoURI
	}
	return ""
}
