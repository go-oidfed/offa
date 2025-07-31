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

## `authority_hints`
<span class="badge badge-purple" title="Value Type">list of uris</span>
<span class="badge badge-red" title="If this option is required or optional">required</span>

The `authority_hints` option is used to specify the Entity IDs of Federation 
Entities that are direct superior to OFFA and that issue a statement about OFFA.
??? file "config.yaml"

    ```yaml
    federation:
        authority_hints:
            - https://ia.example.com
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

## `filter_to_automatic_ops`
<span class="badge badge-purple" title="Value Type">boolean</span>
<span class="badge badge-blue" title="Default Value">`false`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `filter_to_automatic_ops` option is currently unused.

??? file "config.yaml"

    ```yaml
    federation:
        filter_to_automatic_ops: true
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
<span class="badge badge-purple" title="Value Type">boolean</span>
<span class="badge badge-blue" title="Default Value">`false`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `use_entity_collection_endpoint` option indicates if OFFA uses an external
entity collection endpoint (from the federation) to collect OpenID Providers 
in the federation. The collected providers are used to give the user a 
provider selection to they can choose the provider they want to use.
It is generally more performant to rely on an external endpoint.

??? file "config.yaml"

    ```yaml
    federation:
        use_entity_collection_endpoint: true
    ```


## `entity_collection_interval`
<span class="badge badge-purple" title="Value Type">[duration](index.md#time-duration-configuration-options)</span>
<span class="badge badge-blue" title="Default Value">5 minutes</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `entity_collection_interval` option defines in which interval OFFA will 
query the Entity Collection Endpoint or do entity collection on its own.

??? file "config.yaml"

    ```yaml
    federation:
        entity_collection_interval: 1h
    ```

