package server

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/favicon"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	log "github.com/sirupsen/logrus"

	"github.com/go-oidfed/offa/internal/config"
	logger2 "github.com/go-oidfed/offa/internal/logger"
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
				Format:     "${time} ${ip} ${ua} ${latency} - ${status} ${method} ${path} ${locals:requestid}\n",
				TimeFormat: "2006-01-02 15:04:05",
				Output:     logger2.MustGetAccessLogger(),
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
				FileSystem: http.FS(faviconFS),
			},
		),
	)
}

func addStaticFiles(s fiber.Router) {
	s.Use(
		"/static", filesystem.New(
			filesystem.Config{
				Root: newLocalAndOtherSearcherFilesystem(
					joinIfFirstNotEmpty(
						config.Get().Server.WebOverwriteDir, "static",
					), http.FS(staticFS),
				),
			},
		),
	)
}
