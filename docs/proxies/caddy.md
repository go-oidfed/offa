---
description: Configuration of OFFA with a Caddy reverse proxy.
icon: simple/caddy
---

The following example configuration can be used (tweak as needed):

We assume the following project layout:

```tree
caddy
    Caddyfile #(1)!
    config/ 
    data/
docker-compose.yaml #(2)!
offa
    config.yaml #(3)!
```

1. [`caddy/CaddyFile`](#caddycaddyfile)
2. [`docker-compose.yaml`](#docker-composeyaml)
3. [`offa/config.yaml`](#offaconfigyaml)


=== ":material-file-code: `docker-compose.yaml`"

    ```yaml
    services:
      caddy:
        image: caddy:latest
        restart: unless-stopped
        ports:
          - "80:80"
          - "443:443"
        volumes:
          - ./caddy/Caddyfile:/etc/caddy/Caddyfile
          - ./caddy/data:/data
          - ./caddy/config:/config

      offa:
        image: oidfed/offa:main
        restart: unless-stopped
        volumes:
          - ./offa/config.yaml:/config.yaml:ro
          - ./offa:/data

      # This would be your service
      whoami:
        image: containous/whoami
        restart: unless-stopped

    ```

=== ":material-file-code: `caddy/Caddyfile`"

    ```caddy
    offa.example.com {
      reverse_proxy offa:15661
    }

    whoami.example.com {
        forward_auth offa:15661 {
            uri /auth
            copy_headers  X-Forwarded-User X-Forwarded-Groups X-Forwarded-Name X-Forwarded-Email X-Forwarded-Provider X-Forwarded-Subject
        }

        reverse_proxy whoami:80
    }
    ```

=== ":material-file-code: `offa/config.yaml`"

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
      external_resolver:
        enabled: true
      use_entity_collection_endpoint: true
    ```

    For more information about the offa config file, please refer to [OFFA Configuration](../config/index.md).
