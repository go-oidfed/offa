package server

import (
	"slices"
	"time"

	go2 "github.com/adam-hanna/arrayOperations"
	"github.com/go-oidfed/lib/oidfedconst"
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	zutils "github.com/zachmann/go-utils"

	"github.com/go-oidfed/offa/internal/cache"
	"github.com/go-oidfed/offa/internal/config"
	"github.com/go-oidfed/offa/internal/model"
	"github.com/go-oidfed/offa/internal/pkce"
)

const (
	ctypeJSON = "application/json"
	ctypeJWT  = "application/jwt"

	claimIss = "iss"
	claimAud = "aud"
	claimExp = "exp"
)

const browserStateCookieName = "_offa_auth_state"

func doLogin(c *fiber.Ctx, opID, next, loginHint string) error {
	opMetadata, err := federationLeafEntity.ResolveOPMetadata(opID)
	if err != nil {
		return renderError(c, "could not resolve OP metadata", err.Error())
	}
	possibleRegistrationTypes := go2.Intersect(
		config.Get().Federation.
			ClientRegistrationTypes, opMetadata.ClientRegistrationTypesSupported,
	)
	if len(possibleRegistrationTypes) == 0 {
		return renderError(c, "OP and OFFA do not have any commonly supported client registration types", "")
	}
	if slices.Contains(possibleRegistrationTypes, oidfedconst.ClientRegistrationTypeAutomatic) {
		return loginAutomatic(c, opID, next, loginHint)
	}
	if slices.Contains(possibleRegistrationTypes, oidfedconst.ClientRegistrationTypeExplicit) {
		return loginExplicit(c, opID, next, loginHint)
	}
	return renderError(
		c,
		"OP and OFFA do not have any commonly supported client registration types",
		"the OP only supports registration types that are unknown to OFFA",
	)
}

func codeExchange(c *fiber.Ctx) error {
	if e := c.Query("error"); e != "" {
		c.Status(444)
		return renderError(c, e, c.Query("error_description"))
	}

	code := c.Query("code")
	state := c.Query("state")

	stateInfo, err := loadAndValidateState(c, state)
	if err != nil {
		return err
	}
	codeExchanger := codeExchangeAutomatic
	if stateInfo.Explicit {
		codeExchanger = codeExchangeExplicit
	}
	userData, err := codeExchanger(
		c, stateInfo, code, func() {
			clearState(c, state)
		},
	)
	if err != nil {
		return err
	}

	// Normalize for downstream usage
	normalizeClaims(userData)

	if err = createSessionCookie(c, userData); err != nil {
		c.Status(fiber.StatusInternalServerError)
		return renderError(c, "internal server error", err.Error())
	}

	next := stateInfo.Next
	if next == "" {
		next = "/"
	}
	return c.Redirect(next)
}

// normalizeClaims converts slice-like values to []string where reasonable.
// This makes downstream processing consistent with GetString/GetStringSlice.
func normalizeClaims(claims model.UserClaims) {
	for k, v := range claims {
		switch t := v.(type) {
		case []any:
			ss := make([]string, 0, len(t))
			for _, e := range t {
				if s, ok := e.(string); ok {
					ss = append(ss, s)
				}
			}
			claims[k] = ss
		}
	}
}

type stateData struct {
	CodeChallenge pkce.PKCE
	Issuer        string
	BrowserState  string
	Next          string
	Explicit      bool
}

func createSessionCookie(c *fiber.Ctx, userData model.UserClaims) error {
	sessionID, err := zutils.RandomString(128)
	if err != nil {
		return err
	}
	if err = cache.SetSession(sessionID, userData); err != nil {
		return err
	}
	c.Cookie(
		&fiber.Cookie{
			Name:     config.Get().SessionStorage.CookieName,
			Value:    sessionID,
			Domain:   config.Get().SessionStorage.CookieDomain,
			MaxAge:   config.Get().SessionStorage.TTL,
			HTTPOnly: true,
			Secure:   config.Get().Server.Secure,
			SameSite: "none",
		},
	)
	return nil
}

func clearState(c *fiber.Ctx, state string) {
	c.ClearCookie(browserStateCookieName)
	if err := cache.Set(cache.KeyStateData, state, nil, time.Nanosecond); err != nil {
		log.WithError(err).Error("failed to clear state cache")
	}
}

func loadAndValidateState(c *fiber.Ctx, state string) (stateData, error) {
	var stateInfo stateData
	found, err := cache.Get(cache.KeyStateData, state, &stateInfo)
	if err != nil {
		c.Status(fiber.StatusInternalServerError)
		return stateData{}, renderError(c, "internal server error", err.Error())
	}
	if !found {
		c.Status(444)
		return stateData{}, renderError(c, "state mismatch", "")
	}
	if stateInfo.BrowserState != c.Cookies(browserStateCookieName) {
		c.Status(444)
		return stateData{}, renderError(c, "state mismatch", "")
	}
	return stateInfo, nil
}
