package server

import (
	"encoding/json"
	"mime"
	"net/url"
	"slices"
	"strings"
	"time"

	oidfed "github.com/go-oidfed/lib"
	"github.com/gofiber/fiber/v2"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	zutils "github.com/zachmann/go-utils"

	"github.com/go-oidfed/offa/internal/cache"
	"github.com/go-oidfed/offa/internal/config"
	ihttp "github.com/go-oidfed/offa/internal/http"
	"github.com/go-oidfed/offa/internal/model"
	"github.com/go-oidfed/offa/internal/pkce"
)

func loginAutomatic(c *fiber.Ctx, opID, next, loginHint string) error {
	log.Debugf("Starting authorization code flow with automatic client registration for %s", opID)
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

func codeExchangeAutomatic(c *fiber.Ctx, stateInfo stateData, code string, clearState func()) (
	model.UserClaims, error,
) {
	log.Debugf("Doing authorization code exchange with automatic client registration")
	tokenRes, err := performCodeExchange(stateInfo.Issuer, code, stateInfo.CodeChallenge.Verifier())
	if err != nil {
		return nil, err
	}

	clearState()

	// Verify and parse ID token to initial user claims
	userData, err := parseIDToken(stateInfo.Issuer, tokenRes.IDToken)
	if err != nil {
		c.Status(444)
		return nil, renderError(c, "error decoding id token", err.Error())
	}
	log.Debugf("Userclaims from id_token: %+v", userData)

	mergeUserinfoClaims(stateInfo.Issuer, tokenRes.AccessToken, userData)

	return userData, nil
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
