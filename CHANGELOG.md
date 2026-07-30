## OFFA 0.5.0

This is a major release. Federation signing keys can now be synced to authority hints on rotation, trust-anchor JWKS can be auto-refreshed, and the logging stack has migrated from logrus to zerolog. Post-quantum and composite signing algorithms, configurable key announcement lead times, and automatic key rotation round out the headline changes.

### New Features

#### JWKS Sync to Authority Hints on Key Rotation
`federation.authority_hints` entries may now be given as objects (`entity_id` + optional `jwks_sync`) in addition to the legacy plain-string form. Each authority hint can independently opt into one of two sync modes that fire whenever OFFA rotates its federation signing keys (i.e. when `signing.federation.automatic_key_rollover.enabled` is `true`):

- **`push`** — OFFA signs a JWK Set (`application/jwk-set+jwt`) and pushes it to the hint's `federation_jwks_update_endpoint`.
- **`trigger`** — OFFA POSTs its `entity_id` (authenticated with `private_key_jwt`) to the hint's `federation_jwks_update_trigger_endpoint`, asking it to re-fetch OFFA's JWKS.
- **`none`** — no sync (default; equivalent to the plain-string form).

The target endpoint URL and acceptable signing algorithms are resolved dynamically from the authority hint's Entity Configuration at the time of each rotation — no URLs need to be hardcoded. Per-hint options: `jwks_sync.jwt_lifetime` (default 10m), `jwks_sync.timeout` (default 20s), `jwks_sync.headers`. A warning is logged at startup if `jwks_sync` is configured but automatic key rollover is disabled. The initial key seeding (when no key file exists yet) does not trigger sync hooks — only subsequent rotations do.

#### Trust-Anchor JWKS Refreshing
Trust anchors may now set `enable_jwks_update: true` to have OFFA periodically poll and persist their JWKS to `<key_storage>/ta-jwks/`. The refresher is started at boot and stopped/restarted on `SIGHUP` config reload.

#### Key Announcement Lead Time
Two new key-rotation options control how far in advance a new key is published in the JWKS before it becomes active: `key_announcement_lead_time` (fixed duration) and `key_announcement_lead_time_ec_multiplier` (multiplier on EC lifetime; takes precedence). Default is `max(5 × EC lifetime, 24h)`; values shorter than the EC lifetime are clamped with a warning. Available for both `signing.federation` and `signing.oidc`.

#### Post-Quantum & Hybrid Signing Algorithms
Added support for ML-DSA (FIPS 204) and composite PQC-hybrid signatures for both federation and OIDC signing: `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`, and the hybrids `ML-DSA-44-ES256`, `ML-DSA-65-ES256`, `ML-DSA-87-ES384`, `ML-DSA-44-Ed25519`, `ML-DSA-65-Ed25519`, `ML-DSA-87-Ed448`. Also added `ES256K`, and curve-specific `Ed25519` / `Ed448`.

### Improvements

- **Logging migrated from logrus to zerolog.** Output is now human-readable, no-color console text (RFC 3339 timestamp + level + `key=value` fields). The `internal/logger` package exposes a logrus-compatible facade (`Debug`/`Info`/`Warn`/`Error`/`Fatal`, `WithError`, `WithField`, `WithFields`, `Debugf`, …) so call sites are unchanged.
- **go-oidfed library logs consolidated.** The library's internal logs are now routed to the same destination and level as OFFA's internal logs, so all output lands in `offa.log`.
- **Startup algorithm validation.** `signing.federation` and `signing.oidc` algorithms (including `default_alg`) are now validated against the library's supported set at config load; unknown algorithms are fatal with an actionable message instead of failing later during KMS setup.
- **`authority_hints` validation.** Object-form entries must have an `entity_id`, `jwks_sync.mode` must be a known value, and entity IDs must be unique.
- **Curated default OIDC algorithm allow-list** (`ES256`, `ES384`, `ES512`, `Ed25519`, `Ed448`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`) instead of "all supported algorithms".
- The internal logger now defaults to a sane stderr/console writer before `Init` is called (e.g. during the initial config load).

### Bug Fixes

- **Automatic key rotation was silently disabled.** Although the `automatic_key_rollover` config was parsed and validated, `StartAutomaticRotation` was never invoked — rotation never began. This is now corrected for both OIDC and federation keys.

### Dependencies / Build

- Go **1.26** (built with `GOEXPERIMENT=jsonv2` in the Docker image and CI).
- `lestrrat-go/jwx` upgraded v3 → **v4**.
- `go-oidfed/lib` upgraded to **0.11.0**.
- `coreos/go-oidc/v3` 3.18.0 → 3.20.0.
- `gofiber/fiber/v2` 2.52.13 → 2.52.14.
- `redis/go-redis/v9` 9.19.0 → 9.21.0.
- `valyala/fasthttp` 1.71.0 → 1.73.0.
- `bradfitz/gomemcache` and `zachmann/go-utils` bumped.
- `logrus` replaced by `rs/zerolog` v1.35.1.

---

## OFFA 0.4.8

### Bug Fixes

- Fixed a problem with the `essential` metadata policy and array claims.
- Fixed a bug that prevented creation of OIDC signing keys.

**Full Changelog**: https://github.com/go-oidfed/offa/compare/v0.4.7...v0.4.8

---

## OFFA 0.4.7

### New Features

- Publish trust anchors in the entity configuration.

**Full Changelog**: https://github.com/go-oidfed/offa/compare/v0.4.6...v0.4.7

---

## OFFA 0.4.6

### New Features

- Added `publish_informational_claims_in_federation_entity` config option to control whether informational metadata claims are copied from the RP to `federation_entity`.
- Added `extra_fe_metadata` support to customize `federation_entity` metadata.

### Dependencies / Build

- `go-oidfed/lib` 0.10.4 → 0.10.8.
- `valyala/fasthttp` 1.70.0 → 1.71.0.
- `lestrrat-go/jwx/v3` 3.1.0 → 3.1.1.

**Full Changelog**: https://github.com/go-oidfed/offa/compare/v0.4.5...v0.4.6

---

## OFFA 0.4.5

### Dependencies / Build

- `go-oidfed/lib` 0.10.3 → 0.10.4.
- `redis/go-redis/v9` 9.18.0 → 9.19.0.

**Full Changelog**: https://github.com/go-oidfed/offa/compare/v0.4.4...v0.4.5

---

## OFFA 0.4.4

### New Features

- Upgraded `go-oidfed/lib` to `v0.10.3`, which includes changes to signing key storage and (very small) configuration.
- Automatic migration of legacy key formats to the new storage structure.

### Bug Fixes

- Updated helmet middleware configuration to set `CrossOriginEmbedderPolicy=unsafe-none` (fixes #82).
- Fixed integer precision loss in the log output of `UserClaims` (fixes #67).

### Dependencies / Build

- `go-oidfed/lib` bumped to v0.10.3.
- `gofiber/fiber/v2` bumped to 2.52.12.
- `redis/go-redis/v9` bumped to 9.18.0.
- `go-jose/go-jose/v4` bumped to 4.1.4.
- `valyala/fasthttp` bumped to 1.70.0.
- `coreos/go-oidc/v3` bumped to 3.18.0.
- `lestrrat-go/jwx/v3` bumped to 3.1.0.
- `go-resty/resty/v2` bumped to 2.17.2.
- `golang.org/x/oauth2` bumped to 0.35.0.
- `sirupsen/logrus` bumped to 1.9.4.

**Full Changelog**: https://github.com/go-oidfed/offa/compare/v0.4.3...v0.4.4

---

## OFFA 0.4.3

### Bug Fixes

- Fixed RP metadata field name from `request_object_alg_values_supported` to `request_object_signing_alg_values_supported`.

### Dependencies / Build

- `coreos/go-oidc/v3` 3.16.0 → 3.17.0.
- `go-resty/resty/v2` 2.16.5 → 2.17.1.
- `redis/go-redis/v9` 9.17.0 → 9.17.2.
- `golang.org/x/oauth2` 0.33.0 → 0.34.0.
- `lestrrat-go/jwx/v3` 3.0.12 → 3.0.13.
- `gofiber/utils` 1.1.0 → 1.2.0.
- `valyala/fasthttp` 1.68.0 → 1.69.0.

**Full Changelog**: https://github.com/go-oidfed/offa/compare/v0.4.2...v0.4.3

---

## OFFA 0.4.2

### Dependencies / Build

- `golang.org/x/crypto` 0.44.0 → 0.45.0.
- `redis/go-redis/v9` 9.16.0 → 9.17.0.
- `go-oidfed/lib` bumped to 0.8.4.

**Full Changelog**: https://github.com/go-oidfed/offa/compare/v0.4.1...v0.4.2

---

## OFFA 0.4.1

### Dependencies / Build

- Updated `go-oidfed/lib` to 0.8.3.

**Full Changelog**: https://github.com/go-oidfed/offa/compare/v0.4.0...v0.4.1

---

## OFFA 0.4.0

### New Features

- Added support for requiring OPs to have certain trust marks.
- Added multi-platform Docker builds.

### Dependencies / Build

- Upgraded dependencies.
- Upgraded `go-oidfed/lib` to 0.8.1.

**Full Changelog**: https://github.com/go-oidfed/offa/compare/v0.3.1...v0.4.0

---

## OFFA 0.3.1

### Bug Fixes

- Fixed a config check.

**Full Changelog**: https://github.com/go-oidfed/offa/compare/v0.3.0...v0.3.1

---

## OFFA 0.3.0

### New Features

- OFFA now obtains user attributes from userinfo (in addition to the id token).
- Added support for thiss.js (seamless access) for discovery.
- Added support for explicit client registration (experimental).
- Some smaller enhancements.

### Dependencies / Build

- Updated dependencies.

**Full Changelog**: https://github.com/go-oidfed/offa/compare/v0.2.1...v0.3.0

---

## OFFA 0.2.1

### Improvements

- Informational metadata is copied to `federation_entity`.
- Docker container now stops gracefully.
- Allow configuring the network address to which OFFA binds.
- Log the real client IP (header is configurable).

### Dependencies / Build

- Updated dependencies.

**Full Changelog**: https://github.com/go-oidfed/offa/compare/v0.2.0...v0.2.1

---

## OFFA 0.2.0

This is the first official release of OFFA. OFFA was in use before, so the following lists the changes since the last pre-release state.

### New Features

- The Entity Configuration lifetime is now configurable.
- Support for signing key rotation and signing algorithms other than ES512.
- OFFA now offers a default landing page (`/`) that shows information about the user, allowing OFFA to serve as a dummy RP.
- Improved OP selection including a search box.
- Added the ability to forward all OIDC claims as HTTP headers by defining a prefix without listing each one explicitly.
- Improved support for setting Entity Configuration metadata.
- Improved login URL to be compliant with third-party initiated login from OIDC core.

### Breaking Changes

- **Improved config format for durations** (e.g. entity configuration lifetime).
  - **Incompatible change for `federation.entity_collection_interval`.** This was previously given in minutes. If only a number is given, it is now interpreted as seconds. A small number will result in an error. To keep your existing config, append `m` to the number.
- **Config change: signing now has its own config section.** See https://go-oidfed.github.io/offa/config/signing/
