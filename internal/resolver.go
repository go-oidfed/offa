package internal

import (
	"github.com/go-oidfed/lib"
	"github.com/go-oidfed/lib/apimodel"

	"github.com/go-oidfed/offa/internal/config"
)

// metadataResolverProducer builds the RequestObjectProducer used to authenticate
// to federation resolve (and related) endpoints. It is produced from OFFA's
// federation signer and OFFA's entity ID.
func metadataResolverProducer() *oidfed.RequestObjectProducer {
	return oidfed.NewRequestObjectProducer(
		config.Get().Federation.EntityID, FederationSigner(), triggerAssertionLifetime,
	)
}

// multiEndpointResolver is an oidfed.MetadataResolver that races the
// explicitly configured resolve endpoints concurrently (see
// oidfed.ParallelMetadataResolver) and, when they all fail, either falls back
// to smart (per-trust-anchor) resolving followed by local resolving (strategy
// "smart"), or propagates the last error (strategy "strict").
type multiEndpointResolver struct {
	// endpoints races the configured resolve endpoints with a bounded deadline
	// and grace period, so one slow or unresponsive endpoint can no longer
	// delay a fast valid one.
	endpoints oidfed.ParallelMetadataResolver
	// fallback, when non-nil, is used after all endpoints fail (smart strategy).
	fallback oidfed.SmartRemoteMetadataResolver
	strict   bool
}

// SetupMetadataResolver wires OFFA's federation resolve endpoint configuration
// into the library's DefaultMetadataResolver (and DefaultClientAuth). It is
// called from both startup and config reload, and is idempotent.
func SetupMetadataResolver() {
	conf := config.Get()
	if !conf.Federation.ExternalResolver.Enabled {
		oidfed.DefaultMetadataResolver = oidfed.LocalMetadataResolver{}
		return
	}
	producer := metadataResolverProducer()
	oidfed.SetDefaultClientAuth(producer)

	if len(conf.Federation.ExternalResolver.Endpoints) == 0 {
		// Auto-discovery: authenticate per trust anchor's EC.
		oidfed.DefaultMetadataResolver = oidfed.SmartRemoteMetadataResolver{
			ClientAuth: &oidfed.RemoteResolverClientAuth{ROProducer: producer},
		}
		return
	}

	endpoints := make([]oidfed.MetadataResolver, len(conf.Federation.ExternalResolver.Endpoints))
	for i, e := range conf.Federation.ExternalResolver.Endpoints {
		var epProducer *oidfed.RequestObjectProducer
		if e.ClientAuth.Enabled {
			epProducer = producer
		}
		endpoints[i] = oidfed.SimpleRemoteMetadataResolver{
			ResolveEndpoint: e.URL,
			ClientAuth:      epProducer,
		}
	}
	strict := conf.Federation.ExternalResolver.Strategy == config.ExternalResolverStrategyStrict
	oidfed.DefaultMetadataResolver = multiEndpointResolver{
		endpoints: oidfed.ParallelMetadataResolver{
			Resolvers:   endpoints,
			Deadline:    conf.Federation.ExternalResolver.Timeout.Duration(),
			GracePeriod: conf.Federation.ExternalResolver.Grace.Duration(),
		},
		fallback: oidfed.SmartRemoteMetadataResolver{
			ClientAuth: &oidfed.RemoteResolverClientAuth{ROProducer: producer},
		},
		strict: strict,
	}
}

// Resolve implements oidfed.MetadataResolver.
func (r multiEndpointResolver) Resolve(req apimodel.ResolveRequest) (*oidfed.Metadata, error) {
	res, err := r.ResolveResponsePayload(req)
	if err != nil {
		return nil, err
	}
	return res.Metadata, nil
}

// ResolveResponsePayload implements oidfed.MetadataResolver.
func (r multiEndpointResolver) ResolveResponsePayload(req apimodel.ResolveRequest) (
	oidfed.ResolveResponsePayload, error,
) {
	res, err := r.endpoints.ResolveResponsePayload(req)
	if err != nil {
		if !r.strict {
			return r.fallback.ResolveResponsePayload(req)
		}
		return oidfed.ResolveResponsePayload{}, err
	}
	return res, nil
}

// ResolvePossible implements oidfed.MetadataResolver.
func (r multiEndpointResolver) ResolvePossible(req apimodel.ResolveRequest) (bool, bool) {
	validConfirmed, invalidConfirmed := r.endpoints.ResolvePossible(req)
	if validConfirmed || invalidConfirmed {
		return validConfirmed, invalidConfirmed
	}
	if !r.strict {
		return r.fallback.ResolvePossible(req)
	}
	return false, false
}
