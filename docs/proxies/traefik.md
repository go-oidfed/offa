---
description: Configuration of OFFA with a Traefik reverse proxy.
icon: simple/traefikproxy
---

The following example configuration can be used (tweak as needed):

We assume the following project layout and an already running `traefik` (but 
the `traefik` can also be added to the docker compose file):

```tree
docker-compose.yaml #(1)!
offa
    config.yaml #(2)!
```

1. [`docker-compose.yaml`](#docker-composeyaml)
2. [`offa/config.yaml`](#offaconfigyaml)

=== ":material-file-code: `docker-compose.yaml`"
    ```yaml
    services:

      offa:
        image: oidfed/offa:main
        restart: unless-stopped
        volumes:
          - ./offa/config.yaml:/config.yaml:ro
          - ./offa:/data
        expose:
          - 15661
        labels:
          - traefik.enable=true
          - traefik.port=15661
          - traefik.http.routers.https-offa.entryPoints=https
          - traefik.http.routers.https-offa.rule=Host(`offa.example.com`)
          - traefik.http.routers.https-offa.tls=true
          - traefik.http.routers.https-offa.tls.certresolver=le
          - traefik.http.middlewares.offa.forwardauth.address=https://offa.example.com/auth
          - traefik.http.middlewares.offa.forwardauth.trustForwardHeader=true
          - traefik.http.middlewares.offa.forwardauth.authResponseHeaders=X-Forwarded-User,X-Forwarded-Groups,X-Forwarded-Name,X-ForwardedEmail,X-Forwarded-Provider,X-Forwarded-Subject

      whoami:
        image: containous/whoami
        labels:
          - traefik.enable=true
          - traefik.http.routers.https-whoami.rule=Host(`whoami.example.com`)
          - traefik.http.routers.https-whoami.entryPoints=https
          - traefik.http.routers.https-whoami.tls=true
          - traefik.http.routers.https-whoami.tls.certresolver=le
          - traefik.http.routers.https-whoami.middlewares=offa@docker
        restart: unless-stopped

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
        redirect_status: 401
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
