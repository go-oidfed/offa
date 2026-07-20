---
icon: material/script-text
---

Under the `logging` config option the logging behavior and locations can be 
configured.

OFFA logs are produced with [zerolog](https://github.com/rs/zerolog) and written
as human-readable, no-color console text (one line per entry, prefixed with an
RFC 3339 timestamp and the level, e.g. `2026-01-01T12:00:00Z INF message`).
Structured fields (such as the request id or an attached error) are appended as
`key=value` pairs on the same line. The go-oidfed library's internal logs are
routed to the same destination and level as OFFA's internal logs, so all log
output is consolidated.

## `access`
<span class="badge badge-purple" title="Value Type">object</span>
<span class="badge badge-green" title="If this option is required or optional">recommended</span>

Under the `access` option the http access log can be configured.

??? file "config.yaml"

    ```yaml
    logging:
        access:
            dir: /var/log/offa
            stderr: true
    ```

The following options are available:

### `dir`
<span class="badge badge-purple" title="Value Type">directory path</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `dir` option is used to configure the directory where the log file 
should be stored.
If not set, OFFA will not log to file.

### `stderr`
<span class="badge badge-purple" title="Value Type">boolean</span>
<span class="badge badge-blue" title="Default Value">`false`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `stderr` option indicates if OFFA logs to `stderr`.

## `internal`
The `internal` option is used to configure logging for OFFA's internal 
logging, i.e. logging related to what OFFA does.

??? file "config.yaml"

    ```yaml
    logging:
        internal:
            dir: /var/log/offa
            stderr: true
            level: info
            smart:
                enabled: true
                dir: /var/log/offa/errors
    ```

All configuration options from [`access`](#access) also can be used with 
`internal`.
In additional the following options can be used:

### `level`
<span class="badge badge-purple" title="Value Type">enum</span>
<span class="badge badge-blue" title="Default Value">info</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `level` option sets the minimal log level that should be logged.

Valid values are:

- `trace`
- `debug`
- `info`
- `warn` / `warning`
- `error`
- `fatal`
- `panic`

### `smart`

Under the `smart` option 'smart' logging can be enabled and configured. 
Smart logging allows to have a higher (less verbose) log level set for 
general (internal) logging without loosing valuable debug information in 
case errors occure.

If smart logging is enabled, the general logs are still done with the level 
set through the [`level`](#level) option, but if an error occurs a special 
error log is created to a dedicated file. This dedicated error log contains 
all log entries - including all log levels, also levels that normally woud 
not be logged - for that particular request.

#### `enabled`
<span class="badge badge-purple" title="Value Type">boolean</span>
<span class="badge badge-blue" title="Default Value">`false`</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `enabled` option is used to enable smart logging.

#### `dir`
<span class="badge badge-purple" title="Value Type">directory path</span>
<span class="badge badge-blue" title="Default Value">same as the internal logging dir</span>
<span class="badge badge-green" title="If this option is required or optional">optional</span>

The `dir` option is used to specify the directory where smart error log 
files should be stored.
If not set and smart logging is enabled, smart error logs are placed in the 
same directory as the regular internal log file.