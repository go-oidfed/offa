package server

import (
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/go-oidfed/lib"
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"

	"github.com/go-oidfed/offa/internal"
	"github.com/go-oidfed/offa/internal/cache"
	"github.com/go-oidfed/offa/internal/config"
	"github.com/go-oidfed/offa/internal/model"
)

func isTrustedIP(ipStr string) bool {
	if len(config.Get().Server.TrustedNets) == 0 {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, ipNet := range config.Get().Server.TrustedNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func addAuthHandlers(s fiber.Router) {
	path := config.Get().Server.Paths.ForwardAuth
	s.Head(path, func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })
	s.Options(path, func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })
	s.All(
		path, func(c *fiber.Ctx) error {
			if config.Get().DebugAuth {
				fmt.Println("---")
				fmt.Println("Auth Request")
				fmt.Println(c.String())
				for k, h := range c.GetReqHeaders() {
					fmt.Printf("%s: %+v\n", k, h)
				}
				fmt.Println("---")
			}
			clientIP := c.IP()
			if !isTrustedIP(clientIP) {
				log.WithField("ip", clientIP).Info("Blocked untrusted IP")
				return c.Status(fiber.StatusForbidden).SendString("Forbidden: Untrusted Proxy")
			}

			forHost := c.Get(fiber.HeaderXForwardedHost)
			forPath := c.Get("X-Forwarded-Uri")

			var rule *config.AuthRule
			if forHost == "" && forPath == "/" {
				rule = &config.AuthRule{
					ForwardHeaders: config.DefaultForwardHeaders, //TODO
				}
			} else {
				if len(config.Get().Auth) == 0 {
					return c.Status(fiber.StatusForbidden).SendString("Forbidden")
				}
				rule = config.Get().Auth.FindRule(forHost, forPath)
			}
			if rule == nil {
				return c.Status(fiber.StatusForbidden).SendString("Forbidden")
			}

			sessionToken := c.Cookies(config.Get().SessionStorage.CookieName)
			if sessionToken == "" {
				return redirectNext(c, forHost, forPath, rule.RedirectStatusCode)
			}

			userInfos, err := validateSession(sessionToken)
			if err != nil || userInfos == nil {
				if err != nil {
					log.WithError(err).Info("Invalid session")
				}
				return redirectNext(c, forHost, forPath, rule.RedirectStatusCode)
			}

			log.Debugf("auth request Userclaims are: %+v", userInfos)

			if !verifyUser(userInfos, rule.Require) {
				return c.Status(fiber.StatusForbidden).SendString("Forbidden")
			}

			setHeaders(c, rule.ForwardHeaders, userInfos)

			return c.SendStatus(fiber.StatusOK)
		},
	)
}

func verifyUser(
	claims model.UserClaims, require oidfed.SliceOrSingleValue[map[model.Claim]oidfed.SliceOrSingleValue[string]],
) bool {
	if len(require) == 0 {
		return true
	}
	for _, options := range require {
		var optionFailed bool
		for claim, claimRequires := range options {
			claimValue, ok := claims.GetString(claim)
			if ok {
				// string claim
				if len(claimRequires) != 1 {
					optionFailed = true
					break
				}
				if claimValue == claimRequires[0] {
					continue
				} else {
					optionFailed = true
					break
				}
			}
			claimValues, ok := claims.GetStringSlice(claim)
			if ok {
				if internal.SliceIsSubsetOf(claimRequires, claimValues) {
					continue
				} else {
					optionFailed = true
					break
				}
			}
			optionFailed = true
		}
		if !optionFailed {
			return true
		}
	}
	return false
}

func setHeaders(
	c *fiber.Ctx, headerClaims map[string]oidfed.SliceOrSingleValue[model.Claim], userInfos model.UserClaims,
) {
	if headerClaims == nil {
		headerClaims = config.DefaultForwardHeaders
	}
	for header, claim := range headerClaims {
		var value string
		var ok bool
		for _, cl := range claim {
			value, ok = userInfos.GetForHeader(cl)
			if ok {
				break
			}
		}
		if value != "" {
			c.Set(header, value)
		}
	}
}

func validateSession(sessionKey string) (claims model.UserClaims, err error) {
	var found bool
	found, err = cache.GetSession(sessionKey, &claims)
	if !found {
		claims = nil
	}
	return
}

func redirectNext(c *fiber.Ctx, forHost, forPath string, ruleRedirectStatusCode int) error {
	next := url.URL{
		Scheme: c.Get(fiber.HeaderXForwardedProto),
		Host:   forHost,
		Path:   forPath,
	}
	st := ruleRedirectStatusCode
	if st == 0 {
		st = http.StatusSeeOther
	}
	return c.Redirect(
		fmt.Sprintf("%s?next=%s", fullLoginPath, next.String()), st,
	)
}
