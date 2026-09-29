---
icon: material/binoculars
title: OP Discovery
---

Under the `op_discovery` section you configure how OFFA discovers and presents OpenID Providers (OPs) on the login page.

OP discovery can be powered by a local, periodically refreshed list based on your configured trust anchors, by an external thiss.js Discovery Service, or by both at the same time.

## `local`
<span class="badge badge-purple" title="Value Type">object</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

Controls the built‑in OP discovery that builds a local list of OPs from your federation trust anchors and renders a searchable selector on the login page.

??? file "config.yaml"

    ```yaml
    op_discovery:
      local:
        enabled: true
        use_entity_collection_endpoint: true
        entity_collection_interval: 10m
    ```

### `enabled`
<span class="badge badge-purple" title="Value Type">boolean</span>
<span class="badge badge-blue" title="Default Value">`true`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

Enables the built‑in local OP discovery and the OP selector on the login page.
The local discovery is enabled by default and can be disabled by setting 
this option to `false` (in which case one should enable another discovery method).

### `use_entity_collection_endpoint`
<span class="badge badge-purple" title="Value Type">boolean</span>
<span class="badge badge-blue" title="Default Value">`false`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

If enabled, OFFA queries the trust anchor’s Entity Collection endpoint to 
discover OpenID Providers. If disabled or no entity collection endpoint can 
be found, OFFA discovers OPs directly without relying on the collection endpoint.
It is generally more performant to rely on an external endpoint, therefore 
we recommend enabling this option.

### `entity_collection_interval`
<span class="badge badge-purple" title="Value Type">[duration](index.md#time-duration-configuration-options)</span>
<span class="badge badge-blue" title="Default Value">`5m`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

How often OFFA refreshes the local list of OPs. A value of at least 1 minute is recommended.
The `entity_collection_interval` option defines in which interval OFFA 
refreshes the local list of OPs, either by
querying the Entity Collection Endpoint or doing the entity collection on its 
own.

## `thiss.js`
<span class="badge badge-purple" title="Value Type">object</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

Integrates a thiss.js Discovery Service widget on the login page.

??? file "config.yaml"

    ```yaml
    op_discovery:
      thiss.js:
        enabled: true
        url: https://ds.example.org
    ```

### `enabled`
<span class="badge badge-purple" title="Value Type">boolean</span>
<span class="badge badge-blue" title="Default Value">`false`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

Enables rendering of the thiss.js discovery component on the login page.

### `url`
<span class="badge badge-purple" title="Value Type">uri</span>
<span class="badge badge-red" title="If this option is required or optional">required when `enabled`</span>

Base URL of the thiss.js deployment.

## `external`
<span class="badge badge-purple" title="Value Type">object</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

Renders one or more buttons on the login page that link to external OP discovery
services. Each enabled service becomes an anchor-button; clicking it sends the
user to the service so it can identify OFFA and know where to return the user.

??? file "config.yaml"

    ```yaml
    op_discovery:
      external:
        enabled: true
        services:
          - url: https://ds.example.org/discovery
            include_entity_id: true
            button:
              text: Discover via Example DS
              html_class: btn
              custom_css: ""
    ```

### `enabled`
<span class="badge badge-purple" title="Value Type">boolean</span>
<span class="badge badge-blue" title="Default Value">`false`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

Enables rendering of the external OP discovery buttons on the login page.

### `services`
<span class="badge badge-purple" title="Value Type">list</span>
<span class="badge badge-red" title="If this option is required or optional">required when `enabled`</span>

A list of external discovery services to render as buttons.

The button links to `url` and appends a `target_link_uri` query parameter
(always) carrying OFFA's target link URI, and an `entity_id` query parameter
(only when `include_entity_id` is enabled).

#### `url`
<span class="badge badge-purple" title="Value Type">uri</span>
<span class="badge badge-red" title="If this option is required or optional">required when `enabled`</span>

Base URL of the external discovery service. The button links to this URL.

#### `include_entity_id`
<span class="badge badge-purple" title="Value Type">boolean</span>
<span class="badge badge-blue" title="Default Value">`false`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

When enabled, OFFA appends an `entity_id` query parameter carrying its entity
identifier so the discovery service can identify the relying party.

#### `button`
<span class="badge badge-purple" title="Value Type">object</span>
<span class="badge badge-red" title="If this option is required or optional">required</span>

Controls how the button is rendered.

##### `text`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-red" title="If this option is required or optional">required when `enabled`</span>

The button label.

##### `html_class`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

Extra CSS class(es) appended to the button element, in addition to the standard
`btn` class.

##### `custom_css`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

CSS inlined directly onto the button element via its `style` attribute.


## Using both methods

You can enable both `local` and `thiss.js`. The login page will show the local OP selector and, in addition, the thiss.js widget as an alternative discovery path.

