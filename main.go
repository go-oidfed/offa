package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/go-oidfed/lib"
	"github.com/go-oidfed/lib/jwx"

	"github.com/go-oidfed/offa/internal"
	"github.com/go-oidfed/offa/internal/cache"
	"github.com/go-oidfed/offa/internal/config"
	log "github.com/go-oidfed/offa/internal/logger"
	"github.com/go-oidfed/offa/internal/server"
)

func main() {
	handleSignals()
	config.MustLoadConfig()
	log.Init(loggerSettings())
	cache.Init()
	internal.InitKeys()
	for _, c := range config.Get().Federation.TrustMarks {
		if err := c.Verify(
			config.Get().Federation.EntityID, "",
			jwx.NewTrustMarkSigner(internal.FederationSigner()),
		); err != nil {
			log.Fatal(err)
		}
	}
	if config.Get().Federation.UseResolveEndpoint {
		oidfed.DefaultMetadataResolver = oidfed.SmartRemoteMetadataResolver{}
	}
	server.Init()
	if err := server.StartTAJWKSRefresher(); err != nil {
		log.WithError(err).Fatal("could not start TA JWKS Refresher")
	}
	server.Start()
}

// loggerSettings maps the logging section of the loaded configuration into the
// logger.Settings value expected by the logger package. The logger package is
// intentionally independent of the config package (to avoid an import cycle),
// so the translation happens here.
func loggerSettings() log.Settings {
	l := config.Get().Logging
	return log.Settings{
		Access: log.LogOutputSettings{Dir: l.Access.Dir, StdErr: l.Access.StdErr},
		Internal: log.InternalLogSettings{
			LogOutputSettings: log.LogOutputSettings{Dir: l.Internal.Dir, StdErr: l.Internal.StdErr},
			Level:             l.Internal.Level,
			Smart:             log.SmartSettings{Enabled: l.Internal.Smart.Enabled, Dir: l.Internal.Smart.Dir},
		},
	}
}

func handleSignals() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGUSR1)
	go func() {
		for {
			sig := <-signals
			switch sig {
			case syscall.SIGHUP:
				reload()
			case syscall.SIGUSR1:
				reloadLogFiles()
			}
		}
	}()
}

func reload() {
	log.Info("Reloading config")
	config.MustLoadConfig()
	if config.Get().Federation.UseResolveEndpoint {
		oidfed.DefaultMetadataResolver = oidfed.SmartRemoteMetadataResolver{}
	}
	log.SetOutput(loggerSettings())
	log.MustUpdateAccessLogger()
	server.RestartTAJWKSRefresher()
}

func reloadLogFiles() {
	log.Debug("Reloading log files")
	log.SetOutput(loggerSettings())
	log.MustUpdateAccessLogger()
}
