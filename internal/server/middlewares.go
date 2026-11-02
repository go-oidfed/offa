package server

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/compress"
	"github.com/gofiber/fiber/v3/middleware/favicon"
	"github.com/gofiber/fiber/v3/middleware/helmet"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/requestid"
	"github.com/gofiber/fiber/v3/middleware/static"

	"github.com/go-oidfed/offa/internal/config"
	log "github.com/go-oidfed/offa/internal/logger"
)

func addMiddlewares(s fiber.Router) {
	addRecoverMiddleware(s)
	addRequestIDMiddleware(s)
	addLoggerMiddleware(s)
	addFaviconMiddleware(s)
	addStaticFiles(s)
	addHelmetMiddleware(s)
	addCompressMiddleware(s)
}

func addLoggerMiddleware(s fiber.Router) {
	s.Use(
		logger.New(
			logger.Config{
				Format:     "${time} ${ip} ${ua} ${latency} - ${status} ${method} ${path} ${requestid}\n",
				TimeFormat: "2006-01-02 15:04:05",
				Stream:     log.MustGetAccessLogger(),
			},
		),
	)
}

func addCompressMiddleware(s fiber.Router) {
	s.Use(compress.New())
}

func addRecoverMiddleware(s fiber.Router) {
	s.Use(recover.New())
}

func addHelmetMiddleware(s fiber.Router) {
	s.Use(
		helmet.New(
			helmet.Config{
				CrossOriginEmbedderPolicy: "unsafe-none",
			},
		),
	)
}

func addRequestIDMiddleware(s fiber.Router) {
	s.Use(requestid.New())
}

//go:embed favicon.ico
var faviconFS embed.FS

//go:embed web
var _webFS embed.FS
var webFS fs.FS
var staticFS fs.FS
var htmlFS fs.FS

func init() {
	var err error
	webFS, err = fs.Sub(_webFS, "web")
	if err != nil {
		log.WithError(err).Fatal()
	}
	staticFS, err = fs.Sub(webFS, "static")
	if err != nil {
		log.WithError(err).Fatal()
	}
	htmlFS, err = fs.Sub(webFS, "html")
	if err != nil {
		log.WithError(err).Fatal()
	}
}

func addFaviconMiddleware(s fiber.Router) {
	s.Use(
		favicon.New(
			favicon.Config{
				File:       "favicon.ico",
				FileSystem: faviconFS,
			},
		),
	)
}

func addStaticFiles(s fiber.Router) {
	s.Use(
		"/static", static.New(
			"", static.Config{
				FS: httpFilesystemFS{
					hfs: newLocalAndOtherSearcherFilesystem(
						joinIfFirstNotEmpty(
							config.Get().Server.WebOverwriteDir, "static",
						), http.FS(staticFS),
					),
				},
			},
		),
	)
}
