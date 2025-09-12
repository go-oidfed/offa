# Config
OFFA is configured through a single configuration file named `config.yaml`.

## Config File Location

OFFA will search for this file at startup at different locations, the first 
file that is found will be used. Supported locations are:

- `config.yaml`
- `config/config.yaml`
- `/config/config.yaml`
- `/offa/config/config.yaml`
- `/offa/config.yaml`
- `/data/config/config.yaml`
- `/data/config.yaml`
- `/etc/offa/config.yaml`

## Small Example Config File
The following is a small example config file:

??? file "config.yaml"

    ```yaml
    server:

        logging:
          access:
            stderr: true
          internal:
            level: info
            stderr: true

        sessions:
          ttl: 3600
          cookie_domain: example.com

        auth:
          - domain: whoami.example.com
            require:
              groups: users

        federation:
          entity_id: https://offa.example.com
          trust_anchors:
            - entity_id: https://ta.example.com
          authority_hints:
            - https://ta.example.com
          logo_uri: https://offa.example.com/static/img/offa-text.svg
          key_storage: /data
          use_resolve_endpoint: true
          use_entity_collection_endpoint: true
    ```

## Configuration Sections

<div class="grid cards" markdown>

- [:material-server-network: Server](server.md)
- [:material-script-text: Logging](logging.md)
- [:material-signature-freehand: Signing](signing.md)
- [:simple-openid: Federation](federation.md)
- [:material-binoculars: OP Discovery](op_discovery.md)
- [:material-security: Auth](auth.md)
- [:material-cookie: Sessions](sessions.md)
- [:fontawesome-solid-person-digging: `debug_auth`](debug_auth.md)

</div>

## :fontawesome-solid-stopwatch: Time Duration Configuration Options
Some configuration option take a duration, e.g. the lifetime of entity
statements or the entity configuration.

There are different options how to pass a duration in the config file:

- **Number**: If only a number is given, this is the number of seconds.
- **String**: The duration can also be given as a string which supports
  different units.

For a duration string the following units are supported and multiple units
can be used in a single string:

| Symbol | Unit        | Comment            |
|--------|-------------|--------------------|
| `y`    | Year        | = 365 days         |
| `w`    | Week        | = 7 days           |
| `d`    | Day         | = 24 hours         |
| `h`    | Hour        |                    |
| `m`    | Minute      |                    |
| `s`    | Second      |                    |
| `ms`   | Millisecond | SHOULD NOT be used |
| `µs`   | Microsecond | SHOULD NOT be used |
| `ns`   | Nanosecond  | SHOULD NOT be used |


!!! Example "Examples"
```
1y
2w6d
20d
1h30m
```
