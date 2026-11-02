package server

import (
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/template/mustache/v3"

	"github.com/go-oidfed/offa/internal/config"
)

var paths map[string]string

func initHtmls() {
	mustacheFS := newLocalAndOtherSearcherFilesystem(
		joinIfFirstNotEmpty(config.Get().Server.WebOverwriteDir, "html"), http.FS(htmlFS),
	)
	engine := mustache.NewFileSystem(mustacheFS, ".mustache")
	serverConfig.Views = engine

	paths = map[string]string{
		"login": getFullPath(config.Get().Server.Paths.Login),
		"auth":  getFullPath(config.Get().Server.Paths.ForwardAuth),
	}
}

func render(ctx fiber.Ctx, name string, data map[string]any) error {
	data["basepath"] = config.Get().Server.Basepath
	data["paths"] = paths
	return ctx.Render(name, data)
}

func renderError(ctx fiber.Ctx, error, message string) error {
	return render(
		ctx, "error", map[string]any{
			"error":         error,
			"error_message": message,
		},
	)
}
