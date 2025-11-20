---
icon: material/cookie
---

<span class="badge badge-red" title="If this option is required or optional">required</span>

Under the `sessions` option configuration related to session management can 
be changed.

## `ttl`
<span class="badge badge-purple" title="Value Type">integer</span>
<span class="badge badge-blue" title="Default Value">3600</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `ttl` option defines the "time-to-life", i.e. the session lifetime.

??? file "config.yaml"

    ```yaml
    sessions:
        ttl: 86400
    ```

## `redis_addr`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `redis_addr` option is used to pass a network address where a `redis` 
server can be reached. If set, the `redis` instance is used for caching. If 
not given, an in-memory cache is used.

??? file "config.yaml"

    ```yaml
    sessions:
        redis_addr: redis:6379
    ```

## `redis_username`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

Sets the Redis ACL username used to authenticate to the server.
Leave empty when Redis is configured without ACL users.

??? file "config.yaml"

    ```yaml
    sessions:
      redis_addr: "redis:6379"
      redis_username: "app-user"
    ```

## `redis_password`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

Sets the password for Redis authentication. Used with or without `username`
depending on your Redis setup.

??? file "config.yaml"

    ```yaml
    sessions:
      redis_addr: "redis:6379"
      redis_password: "s3cr3t-pass"
    ```

## `redis_db`
<span class="badge badge-purple" title="Value Type">integer</span>
<span class="badge badge-blue" title="Default Value">0</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

Selects the Redis logical database index to use. Defaults to `0` if not
set. Common deployments use `0`; choose another index when sharing a
Redis instance with other applications.

??? file "config.yaml"

    ```yaml
    sessions:
      redis_addr: "redis:6379"
      redis_db: 1
    ```

## `memcached_addr`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-orange" title="If this option is required or optional">required if apache is used</span>

The `memcached_addr` option is used to pass a network address where a `memcached`
server can be reached. If set, the user claims are stored in the `memcached` 
with the format needed by the apache module AuthMemCookie.

Session information is still / also stored in `redis` or in-memory.


??? file "config.yaml"

    ```yaml
    sessions:
        memcached_addr: memcached:11211
    ```

## `memcached_claims`
<span class="badge badge-purple" title="Value Type">mapping / object</span>
<span class="badge badge-blue" title="Default Value">see file example</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `memcached_claims` option is used to specify which information should be 
stored in the `memcached` and from which OIDC claims the information should 
be obtained.

!!! tip "Note"
    
    The following keys are required by AuthMemCookie:

    - UserName
    - Groups

!!! info

    OIDC Claims can be given as a single string or a list of strings. If a 
    list is given OFFA will use the value from the first non-empty claim.

    !!! example

        In the config below `UserName` will be populated with the value in 
        `preferred_username` if that is set, or `sub` otherwise.

The default mapping is as listed in the following `config.yaml` example.

!!! file "config.yaml"

    ```yaml
    sessions:
        memcached_claims:
            UserName:
                - preferred_username
                - sub
            Groups: groups
            Email: email
            Name: name
            GivenName: given_name
            Provider: iss
            Subject: sub
    ```

## `cookie_name`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-blue" title="Default Value">offa-session</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `cookie_name` option is used to set the name of the cookie that holds 
the session token.

??? file "config.yaml"

    ```yaml
    sessions:
        cookie_name: offa
    ```

## `cookie_domain`
<span class="badge badge-purple" title="Value Type">string</span>
<span class="badge badge-red" title="If this option is required or optional">required</span>

The `cookie_domain` option is used to set the domain the session cookie is 
assigned to protect. This must be the same as the domain OFFA is served on 
or a parent domain.

!!! example
    
    If OFFA is accessible via the URI `https://offa.example.com` the domain 
    should be either `offa.example.com` or `example.com`.

??? file "config.yaml"

    ```yaml
    sessions:
        cookie_domain: example.com
    ```

