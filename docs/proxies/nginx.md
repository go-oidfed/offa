---
description: Configuration of OFFA with an NGINX reverse proxy.
icon: simple/nginx
---

The following example configuration can be used (tweak as needed):

We assume the following project layout:

```tree
certbot
    conf/
    webroot/
docker-compose.yaml #(1)!
nginx
    nginx.conf  #(2)!
offa
    config.yaml #(3)!
```

1. [`docker-compose.yaml`](#docker-composeyaml)
2. [`nginx/nginx.conf`](#nginxnginxconf)
3. [`offa/config.yaml`](#offaconfigyaml)

=== ":material-file-code: `docker-compose.yaml`"

    ```yaml
    services:

      nginx:
        image: nginx:stable
        restart: unless-stopped
        ports:
          - "80:80"
          - "443:443"
        volumes:
          - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
          - ./certbot/webroot:/var/www/certbot
          - ./certbot/conf:/etc/letsencrypt
        depends_on:
          - whoami
          - offa


      certbot:
        image: certbot/certbot
        volumes:
          - ./certbot/webroot:/var/www/certbot
          - ./certbot/conf:/etc/letsencrypt
        entrypoint: /bin/sh -c
        command: >
          "certbot certonly --webroot --webroot-path=/var/www/certbot
           --email your@email.com --agree-tos --no-eff-email
           -d whoami.example.com -d offa.example.com"

      offa:
        image: oidfed/offa:main
        restart: unless-stopped
        volumes:
          - ./offa/config.yaml:/config.yaml:ro
          - ./offa:/data
        expose:
          - 15661

      # This would be your service
      whoami:
        image: containous/whoami
        restart: unless-stopped
    ```

=== ":material-file-code: `nginx/nginx.conf`"

    ```nginx
    events {}
    http {

        # For the certbot challenges
        server {
            listen 80;
            server_name whoami.example.com offa.example.com;

            location /.well-known/acme-challenge/ {
                root /var/www/certbot;
            }

            location / {
                return 301 https://$host$request_uri;
            }
        }

        server {
            listen 443 ssl;
            server_name offa.example.com;

            ssl_certificate /etc/letsencrypt/live/offa.example.com/fullchain.pem;
            ssl_certificate_key /etc/letsencrypt/live/offa.example.com/privkey.pem;

            location / {
                proxy_pass http://offa:15661;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
            }
        }

        server {
            listen 443 ssl;
            server_name whoami.example.com;

            ssl_certificate /etc/letsencrypt/live/whoami.example.com/fullchain.pem;
            ssl_certificate_key /etc/letsencrypt/live/whoami.example.com/privkey.pem;

            location / {
                proxy_pass http://whoami:80;

                auth_request     /auth-verify;
                error_page 401 = @error401;
                auth_request_set $auth_cookie $upstream_http_set_cookie;
                add_header Set-Cookie $auth_cookie;

                auth_request_set $auth_redirect $upstream_http_location;
                auth_request_set $auth_user $upstream_http_x_forwarded_user;
                auth_request_set $auth_email $upstream_http_x_forwarded_email;
                auth_request_set $auth_provider $upstream_http_x_forwarded_provider;
                auth_request_set $auth_subject $upstream_http_x_forwarded_subject;
                auth_request_set $auth_groups $upstream_http_x_forwarded_groups;
                auth_request_set $auth_name $upstream_http_x_forwarded_name;


                #proxy_set_header Host $host;
                #proxy_set_header X-Real-IP $remote_addr;
                #proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                #proxy_set_header X-Forwarded-Proto $scheme;
                proxy_set_header X-Forwarded-User $auth_user;
                proxy_set_header X-Forwarded-Email $auth_email;
                proxy_set_header X-Forwarded-Provider $auth_provider;
                proxy_set_header X-Forwarded-Subject $auth_subject;
                proxy_set_header X-Forwarded-Groups $auth_groups;
                proxy_set_header X-Forwarded-Name $auth_name;
            }

            location @error401 {
                internal;
                add_header Set-Cookie $auth_cookie;
                return 303 $auth_redirect;
            }

            location = /auth-verify {
                internal;

                # Direct internal call to the offa container
                proxy_pass http://offa:15661/auth;

                # Forward headers
                proxy_set_header X-Forwarded-Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
                proxy_set_header X-Forwarded-Uri $request_uri;

                proxy_pass_request_body off;
                proxy_set_header Content-Length "";

                proxy_pass_request_headers on;
                auth_request_set $auth_redirect $upstream_http_location;
                add_header Location $auth_redirect;

            }
        }
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

## Notes
- The example setup was tested and works, but there is probably room for 
  improvements; feel free to submit a Pull Request with improved instructions.
- The setup includes the tooling to get certbot working. But a proper setup 
  probably needs some tweaking.
    - Obtaining the first set of certs might need some manual steps; there 
      might be a chicken-egg-problem where nginx won't start without a cert, 
      but certbot requires nginx

