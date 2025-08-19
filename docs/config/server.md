---
icon: material/server-network
---

Under the `server` config option the (http) server can be configured.


## `ip_listen`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `ip_listen` config option is used to set the network address to which to bind to.
If omitted `0.0.0.0` is used.

??? file "config.yaml"

    ```yaml
    server:
        ip_listen: 127.0.0.1
    ```

## `port`
<span class="badge badge-purple" title="Value Type">integer</span>
<span class="badge badge-blue" title="Default Value">15661</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `port` config option is used to set the port at which OFFA starts 
the webserver and listens for incoming requests.
Will only be used if `tls` is not used.
If `tls` is enabled port `443` will be used (and optionally port `80`).

??? file "config.yaml"

    ```yaml
    server:
        port: 4242
    ```

## `tls`

Under the `tls` config option settings related to `tls` can be configured.
It is unlikely that one enables `tls` since a reverse proxy will be used in 
most cases.

If `tls` is enabled port `443` will be used.

??? file "config.yaml"

    ```yaml
    server:
        tls:
            enabled: true
            redirect_http: true
            cert: /path/to/cert
            key: /path/to/key
    ```

### `enabled`
<span class="badge badge-purple" title="Value Type">boolean</span>
<span class="badge badge-blue" title="Default Value">`true`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

If set to `false` `tls` will be disabled. Otherwise, it will automatically be 
enabled, if `cert` and `key` are set.

### `redirect_http`
<span class="badge badge-purple" title="Value Type">boolean</span>
<span class="badge badge-blue" title="Default Value">`true`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `redirect_http` option determines if port `80` should be redirected to 
port `443` or not.

### `cert`
<span class="badge badge-purple" title="Value Type">file path</span>
<span class="badge badge-green" title="If this option is required or optional">required for TLS</span>

The `cert` option is set to the tls `cert` file.

### `key`
<span class="badge badge-purple" title="Value Type">file path</span>
<span class="badge badge-green" title="If this option is required or optional">required for TLS</span>

The `key` option is set to the tls `key` file.

## `trusted_proxies`
<span class="badge badge-purple" title="Value Type">list of strings</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `trusted_proxies` option is used to configure a list of trusted proxies 
by IP address or network range (CIDR notation).
If set, only requests from those proxies / networks are accepted at the 
[forward auth endpoint](#forward_auth) and other 
requests are not accepted. Without setting this option all requests are 
accepted.

??? file "config.yaml"

    ```yaml
    server:
        trusted_proxies:
            - "10.0.0.0/8"
            - "172.16.0.0/12"
            - "192.168.0.0/16"
            - "fc00::/7"
    ```

## `forwarded_ip_header`

<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-blue" title="Default Value">`X-Forwarded-For`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `forwarded_ip_header` option specifies which HTTP header to use for getting the client's real IP address when behind
a proxy.

??? file "config.yaml"

    ```yaml
    server:
        forwarded_ip_header: X-Real-IP
    ```

## `paths`
<span class="badge badge-purple" title="Value Type">mapping / object</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `paths` option is used to set (custom) uri paths for the different 
endpoints.

??? file "config.yaml"

    ```yaml
    server:
        paths:
            login: /login
            forward_auth: /auth
    ```

### `login`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-blue" title="Default Value">`/login`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `login` option can be used to set the uri path under which the login 
endpoint is served.

The login endpoint will serve a webinterface where the user can select an 
OpenID Provider and log in. After a successful login, OFFA sets a session 
cookie and can redirect the user to the target page.

If OFFA is used with [apache and AuthMemCookie](../proxies/apache.md) only 
the login endpoint is needed.

### `forward_auth`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-blue" title="Default Value">`/auth`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `forward_auth` option can be used to set the uri path under which the 
forward auth endpoint is served.

The forward auth endpoint will receive auth requests from the reverse proxy. 
OFFA checks if the user is authenticated and authorised to access the 
requested uri and return the response to the proxy.
If the user is not authenticated, the request is redirected to the login 
endpoint.

## `web_overwrite_dir`
<span class="badge badge-purple" title="Value Type">directory path</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `web_overwrite_dir` config option is used to set a base directory path 
that contains a directory structure with files that will overwrite embedded 
web content.

This option allows to overwrite html pages, css, and other web-related 
content. See https://github.com/go-oidfed/offa/tree/main/internal/server/web 
for the directory structure and content of the embedded files.

??? file "config.yaml"

    ```yaml
    server:
        web_overwrite_dir: /web
    ```
