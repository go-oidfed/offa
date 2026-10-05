---
description: Configuration of OFFA with an apache reverse proxy and mod AuthMemCookie.
icon: simple/apache
---

OFFA can be used with apache by using the
[AuthMemCookie Apache Module](https://zenprojects.github.io/Apache-Authmemcookie-Module/).

The following example configuration can be used (tweak as needed):

We assume the following project layout:
```tree
apache
    Dockerfile #(1)!
    httpd.conf #(2)!
certbot/
docker-compose.yaml #(3)!
offa
    config.yaml #(4)!
```

1. [`apache/Dockerfile`](#apachedockerfile)
2. [`apache/httpd.conf`](#apachehttpdconf)
3. [`docker-compose.yaml`](#docker-composeyaml)
4. [`offa/config.yaml`](#offaconfigyaml)

=== ":material-file-code: `docker-compose.yaml`"

    ```yaml
    services:

      apache:
        build:
          context: ./apache
        restart: unless-stopped
        ports:
          - "80:80"
          - "443:443"
        volumes:
          - ./apache/httpd.conf:/usr/local/apache2/conf/extra/httpd-authmem.conf:ro
          - ./certbot:/etc/letsencrypt:ro
        depends_on:
          - whoami
          - offa

      memcached:
        image: memcached:alpine

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

=== ":material-file-code: `apache/Dockerfile`"

    ```Dockerfile
    FROM httpd:2.4

    # Install build dependencies
    RUN apt-get update && apt-get install -y \
        apache2-dev \
        build-essential \
        git \
        autoconf \
        automake \
        libtool \
        pkg-config \
        curl \
        ca-certificates \
        libevent-dev \
        memcached \
        libmemcached-dev \
        && rm -rf /var/lib/apt/lists/*

    RUN git clone https://github.com/ZenProjects/Apache-Authmemcookie-Module.git /usr/src/authmemcookie && \
        cd /usr/src/authmemcookie && \
        autoconf -f && \
        ./configure --with-libmemcached=/usr --with-apxs=/usr/local/apache2/bin/apxs && \
        make && \
        make install

    RUN ls -l /usr/local/apache2/modules

    RUN echo "LoadModule mod_auth_memcookie_module modules/mod_auth_memcookie.so" \
        >> /usr/local/apache2/conf/httpd.conf
    RUN echo "Include conf/extra/httpd-authmem.conf" \
        >> /usr/local/apache2/conf/httpd.conf

    EXPOSE 443
    CMD ["httpd-foreground"]
    ```

=== ":material-file-code: `apache/httpd.conf`"

    ```apache
    ServerName whoami.example.com

    LoadModule ssl_module modules/mod_ssl.so
    LoadModule proxy_module modules/mod_proxy.so
    LoadModule proxy_http_module modules/mod_proxy_http.so
    LoadModule headers_module modules/mod_headers.so
    LoadModule mod_auth_memcookie_module modules/mod_auth_memcookie.so
    LoadModule rewrite_module modules/mod_rewrite.so

    Listen 443

    <VirtualHost *:443>
        ServerName whoami.example.com

        SSLEngine on
        SSLCertificateFile /etc/letsencrypt/live/whoami.example.com/fullchain.pem
        SSLCertificateKeyFile /etc/letsencrypt/live/whoami.example.com/privkey.pem

        RewriteEngine On
        RewriteRule ^/autherror$ https://offa.example.com/login?next=https://whoami.example.com [R=303,L]

        ProxyPreserveHost On
        ProxyPass "/autherror" !
        ProxyPass / http://whoami:80/
        ProxyPassReverse / http://whoami:80/

        
        <Location />
            AuthType Cookie
            AuthName "OFFA"
        Auth_memCookie_Memcached_Configuration --SERVER=memcached:11211
        Auth_memCookie_SessionTableSize 32
        Auth_memCookie_SetSessionHTTPHeader on
        Auth_memCookie_SetSessionHTTPHeaderPrefix X-Forwarded-
        Auth_memCookie_CookieName offa-session

        ErrorDocument 401 /autherror

            Require valid-user
        </Location>

        <Location "/autherror">
            Require all granted
        Satisfy any
        </Location>


    </VirtualHost>


    <VirtualHost *:443>
        ServerName offa.example.com

        SSLEngine on
        SSLCertificateFile /etc/letsencrypt/live/offa.example.com/fullchain.pem
        SSLCertificateKeyFile /etc/letsencrypt/live/offa.example.com/privkey.pem

        ProxyPreserveHost On
        ProxyPass / http://offa:15661/
        ProxyPassReverse / http://offa:15661/
    </VirtualHost>
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
      memcached_addr: memcached:11211

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
- The current apache config has a caveat:
    - When redirecting to the login page, the original request path is not 
      preserved. 
      Users will be redirected to the service's root after login.
    - I spent a lot of time to get this working correctly, but could not 
      figure it out. A Pull Request to fix this issue is very welcomed.
- TLS: 
    - To obtain the initial set of certificates run:
      ```shell
      docker run --rm -it -p 80:80 -v "$(pwd)/certbot:/etc/letsencrypt" certbot/certbot certonly --standalone -d whoami.example.com
      docker run --rm -it -p 80:80 -v "$(pwd)/certbot:/etc/letsencrypt" certbot/certbot certonly --standalone -d offa.example.com
      ```
    - Figure out automatic renewal on your own.

