package server

import (
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/go-oidfed/lib"
	"github.com/go-oidfed/lib/apimodel"
	"github.com/go-oidfed/lib/oidfedconst"
	"github.com/gofiber/fiber/v2"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	zutils "github.com/zachmann/go-utils"
	"github.com/zachmann/go-utils/ctxutils"

	"github.com/go-oidfed/offa/internal/cache"
	"github.com/go-oidfed/offa/internal/config"
	ihttp "github.com/go-oidfed/offa/internal/http"
	"github.com/go-oidfed/offa/internal/model"
	"github.com/go-oidfed/offa/internal/pkce"
)

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

const browserStateCookieName = "_offa_auth_state"

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

type opOption struct {
	EntityID    string
	DisplayName string
	KeyWords    string
	LogoURI     string
}

var opOptions []opOption

func scheduleBuildOPOptions() {
	conf := config.Get().OPDiscovery.Local
	if !conf.Enabled {
		return
	}
	ticker := time.NewTicker(conf.EntityCollectionInterval.Duration())

	buildOPOptions()

	go func() {
		for range ticker.C {
			buildOPOptions()
		}
	}()
}

func buildOPOptions() {
	filters := []oidfed.EntityCollectionFilter{}
	allOPs := make(map[string]*oidfed.CollectedEntity)
	var options []opOption
	for _, ta := range config.Get().Federation.TrustAnchors {
		var collector oidfed.EntityCollector
		if config.Get().OPDiscovery.Local.UseEntityCollectionEndpoint {
			collector = oidfed.SmartRemoteEntityCollector{TrustAnchors: config.Get().Federation.TrustAnchors.EntityIDs()}
		} else {
			collector = &oidfed.SimpleEntityCollector{}
		}
		ops := oidfed.FilterableVerifiedChainsEntityCollector{
			Collector: collector,
			Filters:   filters,
		}.CollectEntities(
			apimodel.EntityCollectionRequest{
				TrustAnchor: ta.EntityID,
				EntityTypes: []string{oidfedconst.EntityTypeOpenIDProvider},
			},
		)
		for _, op := range ops {
			allOPs[op.EntityID] = op
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
	opOptions = options
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

func showLoginPage(c *fiber.Ctx) error {
	return render(
		c, "login", map[string]interface{}{
			"client_name": config.Get().Federation.ClientName,
			"logo_uri":    config.Get().Federation.LogoURI,
			"login-path":  config.Get().Server.Paths.Login,
			"login-url":   fullLoginPath,
			"entity-id":   config.Get().Federation.EntityID,
			"ops":         opOptions,
			"next":        c.Query("next", config.Get().Federation.EntityID),
			"conf":        config.Get().OPDiscovery,
		},
	)
}

type stateData struct {
	CodeChallenge pkce.PKCE
	Issuer        string
	BrowserState  string
	Next          string
}

func doLogin(c *fiber.Ctx, opID, next, loginHint string) error {
	r, err := zutils.RandomString(256)
	if err != nil {
		c.Status(fiber.StatusInternalServerError)
		return renderError(c, "internal server error", err.Error())
	}
	state := r[:64]
	browserState := r[64:128]
	pkceVerifier := r[128:192]
	nonce := r[192:224]

	pkceChallenge := pkce.NewS256PKCE(pkceVerifier)
	if err = cache.Set(
		cache.KeyStateData, state, stateData{
			CodeChallenge: *pkceChallenge,
			Issuer:        opID,
			BrowserState:  browserState,
			Next:          next,
		}, 5*time.Minute,
	); err != nil {
		c.Status(fiber.StatusInternalServerError)
		return renderError(c, "internal server error", err.Error())
	}
	challenge, err := pkceChallenge.Challenge()
	if err != nil {
		c.Status(fiber.StatusInternalServerError)
		return renderError(c, "internal server error", err.Error())
	}

	params := url.Values{}
	params.Set("nonce", nonce)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", pkceChallenge.Method().String())
	params.Set("prompt", "consent")
	if loginHint != "" {
		params.Set("login_hint", loginHint)
	}

	authURL, err := federationLeafEntity.GetAuthorizationURL(opID, redirectURI, state, scopes, params)
	if err != nil {
		c.Status(fiber.StatusInternalServerError)
		return renderError(c, "internal server error", err.Error())
	}
	c.Cookie(
		&fiber.Cookie{
			Name:     browserStateCookieName,
			Value:    browserState,
			Path:     getFullPath("/redirect"),
			MaxAge:   300,
			HTTPOnly: true,
			Secure:   config.Get().Server.Secure,
		},
	)
	return c.Redirect(authURL, fiber.StatusSeeOther)
}

func codeExchange(c *fiber.Ctx) error {
	// Handle OP error callback
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

	tokenRes, err := performCodeExchange(stateInfo.Issuer, code, stateInfo.CodeChallenge.Verifier())
	if err != nil {
		return err
	}

	clearState(c, state)

	// Parse ID token payload to initial user claims
	userData, err := parseIDToken(tokenRes.IDToken)
	if err != nil {
		c.Status(444)
		c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
		return renderError(c, "error decoding id token", err.Error())
	}
	log.Debugf("Userclaims from id_token: %+v", userData)

	mergeUserinfoClaims(stateInfo.Issuer, tokenRes.AccessToken, userData)

	// Normalize for downstream usage
	normalizeClaims(userData)

	if err := createSessionCookie(c, userData); err != nil {
		c.Status(fiber.StatusInternalServerError)
		return renderError(c, "internal server error", err.Error())
	}

	next := stateInfo.Next
	if next == "" {
		next = "/"
	}
	return c.Redirect(next)
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

func performCodeExchange(issuer, code, codeVerifier string) (*oidfed.OIDCTokenResponse, error) {
	params := url.Values{}
	params.Set("code_verifier", codeVerifier)
	log.WithField("code_verifier", codeVerifier).Info("Code exchange with code verifier")

	tokenRes, errRes, err := federationLeafEntity.CodeExchange(issuer, code, redirectURI, params)
	if err != nil {
		return nil, err
	}
	if errRes != nil {
		return nil, errors.New(errRes.Error + ": " + errRes.ErrorDescription)
	}
	return tokenRes, nil
}

func parseIDToken(idToken string) (model.UserClaims, error) {
	msg, err := jws.ParseString(idToken)
	if err != nil {
		return nil, err
	}
	var userData model.UserClaims
	if err := json.Unmarshal(msg.Payload(), &userData); err != nil {
		return nil, err
	}
	return userData, nil
}

func mergeUserinfoClaims(issuer, accessToken string, userData model.UserClaims) {
	if accessToken == "" {
		return
	}
	opMetadata, err := federationLeafEntity.ResolveOPMetadata(issuer)
	if err != nil {
		log.WithError(err).Warn("could not resolve OP metadata for userinfo endpoint")
		return
	}
	if opMetadata.UserinfoEndpoint == "" {
		return
	}
	resp, err := ihttp.Do().R().SetHeader("Authorization", "Bearer "+accessToken).Get(opMetadata.UserinfoEndpoint)
	if err != nil {
		log.WithError(err).Warn("failed calling userinfo endpoint")
		return
	}
	if !resp.IsSuccess() {
		log.WithFields(log.Fields{"status": resp.StatusCode()}).Warn("userinfo endpoint returned non-200")
		return
	}
	body := resp.Body()
	var userInfoData model.UserClaims
	// Try plain JSON first
	if err := json.Unmarshal(body, &userInfoData); err == nil {
		normalizeClaims(userInfoData)
		for k, v := range userInfoData {
			userData[k] = v
		}
		log.Debugf("Merged userinfo (JSON) claims: %+v", userInfoData)
		return
	}
	// Fallback: try signed JWT
	if msg, jerr := jws.Parse(body); jerr == nil {
		if err := json.Unmarshal(msg.Payload(), &userInfoData); err != nil {
			log.WithError(err).Warn("failed unmarshalling userinfo JWT payload")
			return
		}
		normalizeClaims(userInfoData)
		for k, v := range userInfoData {
			userData[k] = v
		}
		log.Debugf("Merged userinfo (JWT) claims: %+v", userInfoData)
		return
	}
	// Both JSON and JWT failed
	log.Warn("failed parsing userinfo as JSON or JWT")
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
