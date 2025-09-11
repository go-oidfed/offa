package server

import (
	"encoding/json"
	"mime"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-oidfed/lib"
	"github.com/go-oidfed/lib/apimodel"
	"github.com/go-oidfed/lib/oidfedconst"
	"github.com/gofiber/fiber/v2"
	"github.com/lestrrat-go/jwx/v3/jwk"
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

const (
	ctypeJSON = "application/json"
	ctypeJWT  = "application/jwt"

	claimIss = "iss"
	claimAud = "aud"
	claimExp = "exp"
)

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
	ticker := time.NewTicker(config.Get().Federation.EntityCollectionInterval.Duration())

	go buildOPOptions()

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
		if config.Get().Federation.UseEntityCollectionEndpoint {
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
			"ops":         opOptions,
			"next":        c.Query("next"),
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

	// Verify and parse ID token to initial user claims
	userData, err := parseIDToken(stateInfo.Issuer, tokenRes.IDToken)
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

func parseIDToken(issuer string, idToken string) (model.UserClaims, error) {
	opMetadata, err := federationLeafEntity.ResolveOPMetadata(issuer)
	if err != nil {
		return nil, errors.Wrap(err, "could not resolve OP metadata for id_token validation")
	}
	keySet, err := getOPKeySet(opMetadata)
	if err != nil {
		return nil, errors.Wrap(err, "could not resolve OP key set for id_token validation")
	}
	payload, err := jws.Verify([]byte(idToken), jws.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(true)))
	if err != nil {
		return nil, errors.Wrap(err, "id_token signature verification failed")
	}
	// Validate standard claims
	return validateStandardJWTClaims(payload, opMetadata.Issuer, federationLeafEntity.EntityID)
}

// getOPKeySet returns the jwk.Set for the given OP metadata using embedded JWKS if
// available, otherwise fetching from JWKSURI.
func getOPKeySet(opMetadata *oidfed.OpenIDProviderMetadata) (jwk.Set, error) {
	if opMetadata == nil {
		return nil, errors.New("opMetadata is nil")
	}
	if opMetadata.JWKS != nil && opMetadata.JWKS.Set != nil && opMetadata.JWKS.Len() > 0 {
		return opMetadata.JWKS.Set, nil
	}
	if opMetadata.JWKSURI != "" {
		jwksResp, err := ihttp.Do().R().Get(opMetadata.JWKSURI)
		if err != nil {
			return nil, err
		}
		if !jwksResp.IsSuccess() {
			return nil, errors.Errorf("jwks_uri fetch returned status %d", jwksResp.StatusCode())
		}
		set, err := jwk.Parse(jwksResp.Body())
		if err != nil {
			return nil, err
		}
		return set, nil
	}
	return nil, errors.New("no JWKS or jwks_uri available on OP metadata")
}

// validateStandardJWTClaims checks iss equals expectedIssuer, aud contains expectedAud,
// and exp (if present) is in the future.
func validateStandardJWTClaims(payload []byte, expectedIssuer, expectedAud string) (
	claims model.UserClaims,
	err error,
) {
	if err = json.Unmarshal(payload, &claims); err != nil {
		err = errors.Wrap(err, "failed to unmarshal JWT payload for validation")
		return
	}
	iss, ok := claims[claimIss].(string)
	if !ok || iss == "" {
		err = errors.Errorf("JWT missing '%s' claim", claimIss)
		return
	}
	if iss != expectedIssuer {
		err = errors.Errorf("JWT '%s' mismatch: expected %s, got %s", claimIss, expectedIssuer, iss)
		return
	}
	aud, ok := claims[claimAud]
	if !ok {
		err = errors.Errorf("JWT missing '%s' claim", claimAud)
		return
	}
	okAud := false
	switch v := aud.(type) {
	case string:
		okAud = v == expectedAud
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == expectedAud {
				okAud = true
				break
			}
		}
	case []string:
		okAud = slices.Contains(v, expectedAud)
	default:
		if vs, ok := v.([]string); ok {
			okAud = slices.Contains(vs, expectedAud)
		}
	}
	if !okAud {
		err = errors.New("JWT 'aud' does not contain our entity id")
		return
	}
	if expRaw, ok := claims[claimExp]; ok {
		var expUnix int64
		switch x := expRaw.(type) {
		case float64:
			expUnix = int64(x)
		case int:
			expUnix = int64(x)
		case int64:
			expUnix = x
		case json.Number:
			if n, err := x.Int64(); err == nil {
				expUnix = n
			}
		}
		if expUnix != 0 && time.Now().Unix() >= expUnix {
			err = errors.New("JWT expired")
			return
		}
	}
	return
}

func mergeUserinfoClaims(issuer, accessToken string, userData model.UserClaims) {
	if accessToken == "" {
		return
	}
	opMetadata, err := federationLeafEntity.ResolveOPMetadata(issuer)
	if err != nil {
		log.WithError(err).Error("could not resolve OP metadata for userinfo endpoint")
		return
	}
	if opMetadata.UserinfoEndpoint == "" {
		return
	}
	resp, err := ihttp.Do().R().SetHeader("Authorization", "Bearer "+accessToken).Get(opMetadata.UserinfoEndpoint)
	if err != nil {
		log.WithError(err).Error("failed calling userinfo endpoint")
		return
	}
	if !resp.IsSuccess() {
		log.WithFields(log.Fields{"status": resp.StatusCode()}).Error("userinfo endpoint returned non-200")
		return
	}
	ct := resp.Header().Get(fiber.HeaderContentType)
	mt, _, _ := mime.ParseMediaType(ct)
	mt = strings.ToLower(mt)
	body := resp.Body()
	var userInfoData model.UserClaims
	switch mt {
	case ctypeJSON:
		if err = json.Unmarshal(body, &userInfoData); err != nil {
			log.WithError(err).Error("failed parsing userinfo as application/json")
			return
		}
	case ctypeJWT:
		keySet, kerr := getOPKeySet(opMetadata)
		if kerr != nil {
			log.WithError(kerr).Error("could not get OP key set for userinfo verification")
			return
		}
		payload, verr := jws.Verify(body, jws.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(true)))
		if verr != nil {
			log.WithError(verr).Error("userinfo JWT signature verification failed")
			return
		}
		userInfoData, err = validateStandardJWTClaims(payload, opMetadata.Issuer, federationLeafEntity.EntityID)
		if err != nil {
			log.WithError(err).Error("userinfo JWT claims validation failed")
			return
		}
	default:
		// Unsupported or missing content type
		log.WithField(
			"content-type", ct,
		).Error("unsupported or missing userinfo Content-Type; expected application/json or application/jwt")
	}

	normalizeClaims(userInfoData)
	for k, v := range userInfoData {
		userData[k] = v
	}
	log.Debugf("Merged userinfo (JSON) claims: %+v", userInfoData)
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
