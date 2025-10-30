package server

import (
	"context"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	zutils "github.com/zachmann/go-utils"
	"golang.org/x/oauth2"

	"github.com/go-oidfed/offa/internal/cache"
	"github.com/go-oidfed/offa/internal/config"
	"github.com/go-oidfed/offa/internal/model"
	"github.com/go-oidfed/offa/internal/pkce"
)

func loginExplicit(c *fiber.Ctx, opID, next, loginHint string) error {
	log.Debugf("Starting authorization code flow with explicit client registration for %s", opID)
	oidcRP, err := federationLeafEntity.GetExplicitRegistrationOIDCRP(
		context.Background(),
		opID,
	)
	if err != nil {
		c.Status(444)
		return renderError(c, "error during explicit client registration", err.Error())
	}

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
			Explicit:      true,
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
	options := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("prompt", "consent"),
	}
	if loginHint != "" {
		options = append(options, oauth2.SetAuthURLParam("login_hint", loginHint))
	}
	authURL := oidcRP.AuthCodeURL(state, options...)

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

func codeExchangeExplicit(
	c *fiber.Ctx, stateInfo stateData, code string,
	clearState func(),
) (model.UserClaims, error) {
	log.Debugf("Doing authorization code exchange with explicit client registration")
	oidcRP, err := federationLeafEntity.GetExplicitRegistrationOIDCRP(
		context.Background(),
		stateInfo.Issuer,
	)
	if err != nil {
		c.Status(444)
		return nil, renderError(c, "error during explicit client registration", err.Error())
	}
	tokenRes, err := oidcRP.Exchange(context.Background(), code)
	if err != nil {
		c.Status(444)
		return nil, renderError(c, "error during code exchange", err.Error())
	}

	clearState()

	rawIDToken, ok := tokenRes.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		c.Status(444)
		return nil, renderError(c, "missing id_token in token response", "")
	}
	idToken, err := oidcRP.Verify(context.Background(), rawIDToken)
	if err != nil {
		c.Status(444)
		return nil, renderError(c, "failed to verify id_token", err.Error())
	}
	if idToken.AccessTokenHash != "" {
		if err = idToken.VerifyAccessToken(tokenRes.AccessToken); err != nil {
			c.Status(444)
			return nil, renderError(c, "failed to verify access_token", err.Error())
		}
	}
	var userData model.UserClaims
	if err = idToken.Claims(&userData); err != nil {
		c.Status(444)
		return nil, renderError(c, "failed to unmarshal id_token claims", err.Error())
	}

	log.Debugf("Userclaims from id_token: %+v", userData)

	userInfo, err := oidcRP.UserInfo(context.Background(), oauth2.StaticTokenSource(tokenRes))
	if err != nil {
		log.WithError(err).Error("failed to fetch userinfo")
		return userData, nil
	}
	var userInfoData model.UserClaims
	if err = userInfo.Claims(&userInfoData); err != nil {
		log.WithError(err).Error("failed to unmarshal userinfo claims")
		return userData, nil
	}
	log.Debugf("Userclaims from userinfo: %+v", userData)
	for k, v := range userInfoData {
		userData[k] = v
	}
	return userData, nil
}
