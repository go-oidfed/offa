package server

import (
	"path/filepath"

	oidfed "github.com/go-oidfed/lib"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/go-oidfed/offa/internal/config"
)

var taJWKSRefresher *oidfed.TAJWKSRefresher

// StartTAJWKSRefresher initializes and starts the TA JWKS refresher
// Uses the signing key storage directory for persistence
func StartTAJWKSRefresher() error {
	conf := config.Get()

	// Check if any TAs have enable_jwks_update=true
	hasEnabledTA := false
	for _, ta := range conf.Federation.TrustAnchors {
		if ta.EnableJWKSUpdate {
			hasEnabledTA = true
			break
		}
	}

	if !hasEnabledTA {
		log.Debug("TA JWKS refresh not enabled (no trust anchors with enable_jwks_update=true)")
		return nil
	}

	storageDir := conf.Signing.KeyStorage
	if storageDir == "" {
		return errors.New("signing.key_storage must be configured for TA JWKS refresh")
	}

	taJWKSDir := filepath.Join(storageDir, "ta-jwks")

	storage, err := oidfed.NewFileJWKStorage(taJWKSDir)
	if err != nil {
		return errors.Wrap(err, "failed to create TA JWK storage")
	}

	taJWKSRefresher, err = oidfed.NewTAJWKSRefresher(
		&conf.Federation.TrustAnchors,
		storage,
	)
	if err != nil {
		return errors.Wrap(err, "failed to create TA JWKS Refresher")
	}

	if err = taJWKSRefresher.Start(); err != nil {
		return errors.Wrap(err, "failed to start TA JWKS refresher")
	}

	log.Info("TA JWKS refresher started")
	return nil
}

// stopTAJWKSRefresher stops the TA JWKS refresher gracefully
func stopTAJWKSRefresher() {
	if taJWKSRefresher != nil {
		taJWKSRefresher.Stop()
		taJWKSRefresher = nil
		log.Info("TA JWKS refresher stopped")
	}
}

// RestartTAJWKSRefresher stops and restarts the refresher
// Called on SIGHUP when config is reloaded
func RestartTAJWKSRefresher() {
	stopTAJWKSRefresher()
	if err := StartTAJWKSRefresher(); err != nil {
		log.WithError(err).Error("error when restarting TA JWKS Refresher")
	}
}
