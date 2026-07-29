package server

import (
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"

	"github.com/go-oidfed/offa/internal/config"
)

func addUserPageHandler(s fiber.Router) {
	s.Get(
		"/", func(c *fiber.Ctx) error {
			sub := c.Get("X-Forwarded-Sub")
			if sub != "" {
				return renderHeaders(c, c.GetReqHeaders())
			}
			req, err := http.NewRequest("GET", fullAuthPath, nil)
			if err != nil {
				c.Status(fiber.StatusInternalServerError)
				return renderError(c, "Internal Server Error", err.Error())
			}
			req.Header.Set("X-Forwarded-Uri", "/")
			req.AddCookie(
				&http.Cookie{
					Name:  config.Get().SessionStorage.CookieName,
					Value: c.Cookies(config.Get().SessionStorage.CookieName),
				},
			)
			resp, err := (&http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}).Do(req)
			if err != nil {
				c.Status(fiber.StatusInternalServerError)
				return renderError(c, "Internal Server Error", err.Error())
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				c.Status(fiber.StatusInternalServerError)
				return renderError(c, "Internal Server Error", err.Error())
			}
			if resp.StatusCode == http.StatusOK {
				return renderHeaders(c, resp.Header)
			}
			if fasthttp.StatusCodeIsRedirect(resp.StatusCode) {
				c.Status(resp.StatusCode)
				return c.Redirect(resp.Header.Get(fiber.HeaderLocation))
			}
			return renderError(c, "error", string(body))
		},
	)
}

func renderHeaders(c *fiber.Ctx, headers map[string][]string) error {
	type headerData struct {
		Header string
		Value  string
	}
	var hd []headerData
	for h, vs := range headers {
		if strings.HasPrefix(strings.ToLower(h), "oidc") {
			hd = append(
				hd, headerData{
					Header: h,
					Value:  strings.Join(vs, ", "),
				},
			)
		}
	}
	sort.Slice(
		hd, func(i, j int) bool {
			return hd[i].Header < hd[j].Header
		},
	)
	return render(
		c, "user", map[string]any{
			"headers":  hd,
			"username": c.Get("X-Forwarded-User"),
		},
	)
}
