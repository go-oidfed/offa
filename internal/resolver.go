package internal

import (
	"github.com/pkg/errors"

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

// multiEndpointResolver is an oidfed.MetadataResolver that tries one or more
// explicitly configured resolve endpoints in order. If none succeeds it either
// falls back to smart (per-trust-anchor) resolving followed by local resolving
// (strategy "smart"), or propagates the last error (strategy "strict").
type multiEndpointResolver struct {
	endpoints []oidfed.SimpleRemoteMetadataResolver
	// fallback, when non-nil, is used after all endpoints fail (smart strategy).
	fallback oidfed.SmartRemoteMetadataResolver
	// producer is the client-auth producer shared with DefaultClientAuth.
	producer *oidfed.RequestObjectProducer
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

	endpoints := make([]oidfed.SimpleRemoteMetadataResolver, 0, len(conf.Federation.ExternalResolver.Endpoints))
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
		endpoints: endpoints,
		fallback: oidfed.SmartRemoteMetadataResolver{
			ClientAuth: &oidfed.RemoteResolverClientAuth{ROProducer: producer},
		},
		producer: producer,
		strict:   strict,
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
	var lastErr error
	for _, ep := range r.endpoints {
		res, err := ep.ResolveResponsePayload(req)
		if err != nil {
			lastErr = err
			continue
		}
		return res, nil
	}
	if !r.strict {
		return r.fallback.ResolveResponsePayload(req)
	}
	if lastErr == nil {
		lastErr = errors.New("external resolver: no configured resolve endpoint succeeded")
	}
	return oidfed.ResolveResponsePayload{}, lastErr
}

// ResolvePossible implements oidfed.MetadataResolver.
func (r multiEndpointResolver) ResolvePossible(req apimodel.ResolveRequest) (bool, bool) {
	for _, ep := range r.endpoints {
		validContained, invalidConfirmed := ep.ResolvePossible(req)
		if validContained || invalidConfirmed {
			return validContained, invalidConfirmed
		}
	}
	if !r.strict {
		return r.fallback.ResolvePossible(req)
	}
	return false, false
}
