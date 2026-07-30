---
icon: material/openid
---
<span class="badge badge-red" title="If this option is required or optional">required</span>

Under the `federation` option configuration related to OpenID Federation 
is set.

## `entity_id`
<span class="badge badge-purple" title="Value Type">uri</span>
<span class="badge badge-red" title="If this option is required or optional">required</span>

The `entity_id` option is used to set the Federation Entity ID.

??? file "config.yaml"

    ```yaml
    federation:
        entity_id: https://example.com
    ```

## `client_name`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-blue" title="Default Value">OFFA - Openid Federation Forward Auth</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `client_name` option is used to set a custom client name.

??? file "config.yaml"

    ```yaml
    federation:
        client_name: My Service
    ```

## `client_uri`
<span class="badge badge-purple" title="Value Type">uri</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `client_uri` option is used to set a client URI to be published in the relying party metadata in the entity 
configuration.

??? file "config.yaml"

    ```yaml
    federation:
        client_uri: https://client.example.com
    ```
## `display_name`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `display_name` option is used to set a display name to be published in the relying party metadata.

??? file "config.yaml"

    ```yaml
    federation:
        display_name: My Service Display Name
    ```

## `description`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `description` option is used to set a description to be published in the relying party metadata.

??? file "config.yaml"

    ```yaml
    federation:
        description: This is a description of the service
    ```

## `keywords`
<span class="badge badge-purple" title="Value Type">list of strings</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `keywords` option is used to set keywords to be published in the relying party metadata.

??? file "config.yaml"

    ```yaml
    federation:
        keywords:
            - service
            - authentication
            - federation
    ```

## `contacts`
<span class="badge badge-purple" title="Value Type">list of strings</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `contacts` option is used to set contact information to be published in the relying party metadata.

??? file "config.yaml"

    ```yaml
    federation:
        contacts:
            - admin@example.com
            - support@example.com
    ```

## `policy_uri`
<span class="badge badge-purple" title="Value Type">uri</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `policy_uri` option is used to set a URI to the privacy policy to be published in the relying party metadata.

??? file "config.yaml"

    ```yaml
    federation:
        policy_uri: https://example.com/privacy-policy
    ```

## `tos_uri`
<span class="badge badge-purple" title="Value Type">uri</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `tos_uri` option is used to set a URI to the terms of service to be published in the relying party metadata.

??? file "config.yaml"

    ```yaml
    federation:
        tos_uri: https://example.com/terms-of-service
    ```

## `information_uri`
<span class="badge badge-purple" title="Value Type">uri</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `information_uri` option is used to set a URI to additional information about the service to be published in the relying party metadata.

??? file "config.yaml"

    ```yaml
    federation:
        information_uri: https://example.com/info
    ```

## `logo_uri`
<span class="badge badge-purple" title="Value Type">uri</span>
<span class="badge badge-blue" title="Default Value"><entity_id\>/static/img/offa-text.svg</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `logo_uri` option is used to set a custom logo uri. By default, the OFFA 
logo is used.

??? file "config.yaml"

    ```yaml
    federation:
        logo_uri: https://static.example.com/logo.png
    ```

## `organization_name`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `organization_name` option is used to set the organization name
published in the OpenID Federation Entity Configuration.

??? file "config.yaml"

    ```yaml
    federation:
        organization_name: Example Organization
    ```

## `organization_uri`
<span class="badge badge-purple" title="Value Type">uri</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `organization_uri` option is used to set a URI to the organization's website to be published in the relying party metadata.

??? file "config.yaml"

    ```yaml
    federation:
        organization_uri: https://organization.example.com
    ```

## `publish_informational_claims_in_federation_entity`
<span class="badge badge-purple" title="Value Type">boolean</span>
<span class="badge badge-blue" title="Default Value">`true`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `publish_informational_claims_in_federation_entity` option controls whether informational metadata claims
(such as `organization_name`, `display_name`, `contacts`, `policy_uri`, etc.) are published in both the
`openid_relying_party` and `federation_entity` metadata sections of the Entity Configuration, or only in the
`openid_relying_party` section.

When set to `true` (default), OFFA automatically copies consistent informational claims from the relying party
metadata to the federation entity metadata. This ensures that these claims are available at both levels of the
federation hierarchy.

When set to `false`, informational claims are only published in the `openid_relying_party` metadata section and
are not duplicated in the `federation_entity` section. This can be useful if you want to keep the federation
entity metadata minimal or if you want to explicitly control what appears in each metadata section separately.

??? file "config.yaml"

    ```yaml
    federation:
        # Publish informational claims in both relying_party and federation_entity (default)
        publish_informational_claims_in_federation_entity: true
    ```

    ```yaml
    federation:
        # Only publish informational claims in relying_party, not in federation_entity
        publish_informational_claims_in_federation_entity: false
    ```

!!! info "Informational Claims"

    The following informational claims are affected by this setting:
    
    - `organization_name`
    - `display_name`
    - `description`
    - `logo_uri`
    - `policy_uri`
    - `information_uri`
    - `tos_uri`
    - `contacts` (list)
    - `keywords` (list)
    
    These claims are only copied to the federation entity metadata if they have consistent values across all 
    metadata types that define them. If different values are specified for different metadata types, the claims 
    are not copied to avoid conflicts.

## `extra_rp_metadata`
<span class="badge badge-purple" title="Value Type">mapping / object</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `extra_rp_metadata` option is used to add custom key-value pairs to the relying party metadata in the entity configuration.

??? file "config.yaml"

    ```yaml
    federation:
        extra_rp_metadata:
            custom_field: custom_value
            another_field: another_value
    ```

## `extra_fe_metadata`
<span class="badge badge-purple" title="Value Type">mapping / object</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `extra_fe_metadata` option is used to add custom key-value pairs to the `federation_entity` metadata section in the entity configuration.

This option is applied **before** any automatic copying of informational claims (controlled by [`publish_informational_claims_in_federation_entity`](#publish_informational_claims_in_federation_entity)). This means that values specified in `extra_fe_metadata` take precedence over automatically copied claims. If a field is set in `extra_fe_metadata`, it will not be overwritten by the automatic copying mechanism.

When `publish_informational_claims_in_federation_entity` is set to `true` (default), OFFA will still automatically copy consistent informational claims from other metadata sections to the federation entity metadata, but only for fields that are not already defined in `extra_fe_metadata`.

??? file "config.yaml"

    ```yaml
    federation:
        extra_fe_metadata:
            custom_federation_field: custom_value
            another_federation_field: another_value
    ```

## `extra_entity_configuration_data`
<span class="badge badge-purple" title="Value Type">mapping / object</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `extra_entity_configuration_data` option is used to add custom key-value pairs to the entity configuration.

??? file "config.yaml"

    ```yaml
    federation:
        extra_entity_configuration_data:
            custom_entity_field: custom_value
            another_entity_field: another_value
    ```

## `scopes`
<span class="badge badge-purple" title="Value Type">list of strings</span>
<span class="badge badge-green" title="If this option is required or optional">recommended</span>

The `scopes` option is used to set which scopes should be requested from the 
OpenID Providers.

??? file "config.yaml"

    ```yaml
    federation:
        scopes:
            - openid
            - profile
            - email
    ```

## `trust_anchors`
<span class="badge badge-purple" title="Value Type">list</span>
<span class="badge badge-red" title="If this option is required or optional">required</span>

The `trust_anchors` option is used to specify the Trust Anchors that should 
be used.

??? file "config.yaml"

    ```yaml
    federation:
        trust_anchors:
            - entity_id: https://ta.example.com
            - entity_id: https://other-ta.example.org
              jwks: {...}
              # jwks_file: /path/to/ta.jwks        # alternative to inline jwks
              # enable_jwks_update: true           # enables automatic polling
              # key_poll_interval: 2h              # optional, defaults to TA's EC lifetime
    ```

For each list element the following options are defined:

### `entity_id`
<span class="badge badge-purple" title="Value Type">uri</span>
<span class="badge badge-red" title="If this option is required or optional">required</span>

The `entity_id` of the Trust Anchor.

### `jwks`
<span class="badge badge-purple" title="Value Type">jwks</span>
<span class="badge badge-green" title="If this option is required or optional">recommended</span>

The `jwks` of the Trust Anchor that was obtained out-of-band. If omitted, it 
will be obtained from the Trust Anchor's Entity Configuration and implicitly 
trusted. In that case you are trusting TLS.

!!! tip

    We recommend to provide the `jwks` as `json`. `json` is valid `yaml` and 
    can just be included. This way you can pass the whole `jwks` in a single 
    line.

### `jwks_file`
<span class="badge badge-purple" title="Value Type">path</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

Path to a file containing the Trust Anchor's JWKS (JSON). This is an alternative
to providing the JWKS inline via [`jwks`](#jwks); if both are given, `jwks_file`
takes precedence. The JWKS is loaded from the file at startup. When
[`enable_jwks_update`](#enable_jwks_update) is `true`, updated JWKS are also
persisted back to this file.

### `enable_jwks_update`
<span class="badge badge-purple" title="Value Type">boolean</span>
<span class="badge badge-blue" title="Default Value">false</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

If `true`, OFFA periodically polls the Trust Anchor's Entity Configuration for
JWKS changes and updates the stored JWKS automatically. When set,
[`signing.key_storage`](signing.md#key_storage) must be configured, as the
refreshed JWKS are persisted under `<key_storage>/ta-jwks/`. A
[`jwks_file`](#jwks_file) may additionally be given to persist the JWKS to a
custom location.

### `key_poll_interval`
<span class="badge badge-purple" title="Value Type">[duration](index.md#time-duration-configuration-options)</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The interval at which the Trust Anchor's JWKS is polled when
[`enable_jwks_update`](#enable_jwks_update) is `true`. If omitted, the Trust
Anchor's Entity Configuration lifetime is used as the poll interval.

## `authority_hints`
<span class="badge badge-purple" title="Value Type">list of uris / objects</span>
<span class="badge badge-red" title="If this option is required or optional">required</span>

The `authority_hints` option is used to specify the Entity IDs of Federation 
Entities that are direct superior to OFFA and that issue a statement about OFFA.

Each entry may be given either as a plain string (the entity ID) or as an
object. The object form additionally allows opting into syncing rotated
**federation** keys to that authority hint whenever OFFA's federation signing
keys are rotated.

### Syncing rotated federation keys to authority hints

When OFFA rotates its federation signing keys (i.e. when
[`signing.federation.automatic_key_rollover.enabled`](signing.md) is `true`),
it can notify selected authority hints so they learn about the new keys without
waiting for them to re-fetch OFFA's Entity Configuration. This is configured
per authority hint via the `jwks_sync` block and is independent for each hint.

`jwks_sync.mode` selects one of two mechanisms:

| Mode      | lib hook            | What happens                                                                                                                                                            |
|-----------|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `none`    | —                   | No sync (default; equivalent to the plain-string form).                                                                                                                 |
| `push`    | `JWKSUpdateHook`    | OFFA pushes a signed JWK Set (`application/jwk-set+jwt`) to the hint's `federation_jwks_update_endpoint`.                                                               |
| `trigger` | `TriggerUpdateHook` | OFFA POSTs its entity_id (may be authenticated with `private_key_jwt`) to the <br/>hint's `federation_jwks_update_trigger_endpoint`, asking it to re-fetch OFFA's JWKS. |

In both modes the target endpoint URL and the acceptable signing algorithms
are resolved dynamically from the authority hint's Entity Configuration at the
time of each rotation (served from OFFA's EC cache), so no URLs need to be
hardcoded. The signed JWK Set (push) and the `private_key_jwt` assertion
(trigger) are both signed with OFFA's federation signing key.

!!! note

    `jwks_sync` only applies to **federation** keys, never to OIDC signing
    keys. It only fires when
    `signing.federation.automatic_key_rollover.enabled` is `true`; otherwise
    a warning is logged at startup and the sync never fires. The very first
    key seeding (when no key file exists yet) does not trigger a sync; only
    subsequent rotations do.

??? file "config.yaml"

    ```yaml
    federation:
        authority_hints:
            # Legacy plain-string form: no sync.
            - https://ia.example.com
            # Object form: push a signed JWKS to this hint on each rotation.
            - entity_id: https://lh1.example.com
              jwks_sync:
                mode: push
                jwt_lifetime: 10m   # lifetime of the signed JWKS JWT (default: 10m)
                timeout: 20s        # HTTP timeout (default: 20s)
                headers:            # optional extra HTTP headers
                  X-Custom: value
            # Object form: ask this hint to re-fetch OFFA's JWKS.
            - entity_id: https://lh2.example.com
              jwks_sync:
                mode: trigger
    ```

#### `jwks_sync.mode`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-blue" title="Default Value">none</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

One of `none`, `push`, or `trigger` (see the table above).

#### `jwks_sync.jwt_lifetime`
<span class="badge badge-purple" title="Value Type">[duration](index.md#time-duration-configuration-options)</span>
<span class="badge badge-blue" title="Default Value">10 minutes</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The lifetime (`exp` - `iat`) of the signed JWK Set JWT sent in `push` mode.
Ignored in other modes.

#### `jwks_sync.timeout`
<span class="badge badge-purple" title="Value Type">[duration](index.md#time-duration-configuration-options)</span>
<span class="badge badge-blue" title="Default Value">20 seconds</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The HTTP client timeout for the sync request.

#### `jwks_sync.headers`
<span class="badge badge-purple" title="Value Type">map of string to string</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

Additional HTTP headers set on the sync request.

## `configuration_lifetime`
<span class="badge badge-purple" title="Value Type">[duration](index.md#time-duration-configuration-options)</span>
<span class="badge badge-blue" title="Default Value">1 day</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `configuration_lifetime` option sets the lifetime of Entity Configurations, i.e. this options defines for how long
the Entity Configuration JWTs are valid.

??? file "config.yaml"

    ```yaml
    federation:
        configuration_lifetime: 1w
    ```
`

## `key_storage`
<span class="badge badge-red">deprecated</span>

The `key_storage` option is deprecated. Use [`signing.key_storage`](signing.md) instead.

## `client_registration_types`
<span class="badge badge-purple" title="Value Type">list of strings</span>
<span class="badge badge-blue" title="Default Value">["automatic", "explicit"]</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `client_registration_types` option specifies which client registration types OFFA supports.
This setting is also published in the relying party metadata as part of the entity configuration.

Two registration types are supported as defined by the OpenID Federation specification:
- `automatic`
- `explicit`

By default, both registration types are enabled.
You can also specify only one registration type if needed:

??? file "config.yaml"

    ```yaml
    federation:
        client_registration_types:
            - explicit
    ```

## `trust_marks`
<span class="badge badge-purple" title="Value Type">list of trust mark configs</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `trust_marks` option is used to set Trust Marks that should be published 
in the Entity Configuration.

??? file "config.yaml"

    ```yaml
    federation:
        trust_marks:
            - trust_mark_type: https://example.com/tm
              trust_mark_issuer: https://example.com/tmi
              refresh: true
              min_lifetime: 300
              refresh_grace_period: 7200
    ```

Each Trust Mark Config has the following options defined:

### `trust_mark_type`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-red" title="If this option is required or optional">required</span>

The `trust_mark_type` option sets the Identifier for the type of this Trust 
Mark.

### `trust_mark_issuer`
<span class="badge badge-purple" title="Value Type">uri</span>
<span class="badge badge-red" title="If this option is required or optional">required if `trust_mark_jwt` not given</span>

The `trust_mark_issuer` option is used to set the Entity ID of the Trust 
Mark Issuer of this Trust Mark.

Either a Trust Mark JWT (`trust_mark_jwt`) must be given or the Trust Mark 
Issuer (`trust_mark_issuer`).

If this option is given, [`refresh`](#refresh) will be set to `true` and OFFA 
will 
obtain Trust Mark JWTs for this Trust Mark Type dynamically.

### `trust_mark_jwt`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-red" title="If this option is required or optional">required if `trust_mark_issuer` not given</span>

The `trust_mark_jwt` option is used to set a Trust Mark JWT string. This 
will be published in the Entity Configuration.
If the set Trust Mark JWT expires, it either must be manually updated before 
expiration, or automatic refreshing must be enabled through the [`refresh`](#refresh) 
option.

### `refresh`
<span class="badge badge-purple" title="Value Type">boolean</span>
<span class="badge badge-blue" title="Default Value">`false`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `refresh` option indicates if this Trust Mark should automatically be 
refreshed. If set to `true`, OFFA will fetch a new Trust Mark JWT from 
the Trust Mark Issuer before the 
old one expires, assuring that always a valid Trust Mark JWT is published in 
the Entity Configuration.

### `min_lifetime`
<span class="badge badge-purple" title="Value Type">integer</span>
<span class="badge badge-blue" title="Default Value">10</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `min_lifetime` option is used to set a minimum lifetime in seconds on 
this Trust Mark. If [`refresh`](#refresh) is set to `true` OFFA will assure 
that the Trust Mark JWT published in the Entity Configuration will not 
expire before this lifetime whenever an Entity Configuration is requested.

### `refresh_grace_period`
<span class="badge badge-purple" title="Value Type">integer</span>
<span class="badge badge-blue" title="Default Value">3600</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `refresh_grace_period` option is used to set a grace period given in 
seconds. The default grace period is one hour. If [`refresh`](#refresh) is 
set to `true`, OFFA checks if the Trust Mark expires within the defined grace 
period, whenever its Entity Configuration is requested. If the Trust Mark 
expires within the grace period the old (but still valid) Trust Mark JWT 
will still be included in the Entity Configuration, but in parallel OFFA 
will refresh it by requesting a new Trust Mark JWT from the Trust Mark Issuer.

This allows OFFA to proactively request Trust Mark JWTs that are expiring 
soon in the background.

## `use_resolve_endpoint`
<span class="badge badge-purple" title="Value Type">boolean</span>
<span class="badge badge-blue" title="Default Value">`false`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `use_resolve_endpoint` option indicates if OFFA uses an external 
resolver (from the federation) to resolve Trust Chains or does the resolving 
by its own.
It is generally more performant to rely on an external resolver.

??? file "config.yaml"

    ```yaml
    federation:
        use_resolve_endpoint: true
    ```


## `use_entity_collection_endpoint`
<span class="badge badge-red">deprecated</span>

The `use_entity_collection_endpoint` option is deprecated.
Use [`op_discovery.local.use_entity_collection_endpoint`](op_discovery.md#use_entity_collection_endpoint) 
instead.

## `entity_collection_interval`
<span class="badge badge-red">deprecated</span>

The `entity_collection_interval` option is deprecated.
Use [`op_discovery.local.entity_collection_interval`](op_discovery.md#entity_collection_interval) 
instead.

## `required_op_trust_marks`
<span class="badge badge-purple" title="Value Type">list of strings</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `required_op_trust_marks` option is used to specify Trust Mark Type identifiers.
OpenID Providers must have a valid Trust Mark of the specified type to be accepted by OFFA.
When this option is configured, OFFA will only allow authentication through OpenID Providers that have valid Trust 
Marks for all the specified Trust Mark Types.

This setting provides an additional layer of security and compliance by ensuring that only OpenID Providers with approved trust marks can be used for authentication.

??? file "config.yaml"

    ```yaml
    federation:
        required_op_trust_marks:
            - https://example.com/trust-mark/foobar
            - https://example.com/trust-mark/gdpr-compliant
    ```

