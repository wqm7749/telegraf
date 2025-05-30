# Nginx Upstream Check Input Plugin

This plugin gathers metrics from the [Nginx web server][nginx] using the
[upstream check module][upstream_check_module]. This module periodically sends
the configured requests to servers in the Nginx's upstream determining their
availability.

⭐ Telegraf v1.10.0
🏷️ server, web
💻 all

[nginx]: https://www.nginx.com
[upstream_check_module]: https://github.com/yaoweibin/nginx_upstream_check_module

## Global configuration options <!-- @/docs/includes/plugin_config.md -->

In addition to the plugin-specific configuration settings, plugins support
additional global and plugin configuration settings. These settings are used to
modify metrics, tags, and field or create aliases and configure ordering, etc.
See the [CONFIGURATION.md][CONFIGURATION.md] for more details.

[CONFIGURATION.md]: ../../../docs/CONFIGURATION.md#plugins

## Configuration

```toml @sample.conf
# Read nginx_upstream_check module status information (https://github.com/yaoweibin/nginx_upstream_check_module)
[[inputs.nginx_upstream_check]]
  ## An URL where Nginx Upstream check module is enabled
  ## It should be set to return a JSON formatted response
  url = "http://127.0.0.1/status?format=json"

  ## HTTP method
  # method = "GET"

  ## Optional HTTP headers
  # headers = {"X-Special-Header" = "Special-Value"}

  ## Override HTTP "Host" header
  # host_header = "check.example.com"

  ## Timeout for HTTP requests
  timeout = "5s"

  ## Optional HTTP Basic Auth credentials
  # username = "username"
  # password = "pa$$word"

  ## Optional TLS Config
  # tls_ca = "/etc/telegraf/ca.pem"
  # tls_cert = "/etc/telegraf/cert.pem"
  # tls_key = "/etc/telegraf/key.pem"
  ## Use TLS but skip chain & host verification
  # insecure_skip_verify = false
```

## Metrics

- Measurement
  - fall (The number of failed server check attempts, counter)
  - rise (The number of successful server check attempts, counter)
  - status (The reporter server status as a string)
  - status_code (The server status code. 1 - up, 2 - down, 0 - other)

The "status_code" field most likely will be the most useful one because it
allows you to determine the current state of every server and, possible, add
some monitoring to watch over it. InfluxDB can use string values and the
"status" field can be used instead, but for most other monitoring solutions the
integer code will be appropriate.

### Tags

- All measurements have the following tags:
  - name (The hostname or IP of the upstream server)
  - port (The alternative check port, 0 if the default one is used)
  - type (The check type, http/tcp)
  - upstream (The name of the upstream block in the Nginx configuration)
  - url (The status url used by telegraf)

## Example Output

When run with:

```sh
./telegraf --config telegraf.conf --input-filter nginx_upstream_check --test
```

It produces:

```text
nginx_upstream_check,host=node1,name=192.168.0.1:8080,port=0,type=http,upstream=my_backends,url=http://127.0.0.1:80/status?format\=json fall=0i,rise=100i,status="up",status_code=1i 1529088524000000000
nginx_upstream_check,host=node2,name=192.168.0.2:8080,port=0,type=http,upstream=my_backends,url=http://127.0.0.1:80/status?format\=json fall=100i,rise=0i,status="down",status_code=2i 1529088524000000000
```
