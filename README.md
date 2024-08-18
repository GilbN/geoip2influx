# [Geoip2Influx](https://github.com/gilbN/geoip2influx)

[![Docker Cloud Build Status](https://img.shields.io/docker/cloud/build/gilbn/geoip2influx?style=for-the-badge)](https://hub.docker.com/r/gilbn/geoip2influx/builds)
[![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/gilbn/geoip2influx?color=blue&style=for-the-badge)](https://hub.docker.com/r/gilbn/geoip2influx)
[![Docker Pulls](https://img.shields.io/docker/pulls/gilbn/geoip2influx?color=blue&style=for-the-badge)](https://hub.docker.com/r/gilbn/geoip2influx)
[![GitHub](https://img.shields.io/github/license/gilbn/geoip2influx?color=blue&style=for-the-badge)](https://github.com/gilbN/geoip2influx/blob/master/LICENSE)
[![Discord](https://img.shields.io/discord/591352397830553601?color=blue&style=for-the-badge)](https://discord.gg/HSPa4cz)
[![](https://img.shields.io/badge/Blog-technicalramblings.com-blue?style=for-the-badge)](https://technicalramblings.com/)
***

A python script that will parse the nginx access.log and send geolocation metrics and log metrics to InfluxDB

![](https://i.imgur.com/mh0IhYA.jpg)

### For the linuxserver/letsencrypt docker mod, click here : https://github.com/linuxserver/docker-mods/tree/swag-geoip2influx

***

## Usage

### Enviroment variables:

These are the **default** values for all envs. 
Add the ones that differ on your system. 

| Environment Variable | Example Value | Description |
| -------------------- | ------------- | ----------- |
| NGINX_LOG_PATH | /config/log/nginx/access.log | Container path for Nginx logfile , defaults to the example. |
| GEO_MEASUREMENT | geoip2influx | InfluxDB measurement name for geohashes. Optional, defaults to the example. |
| LOG_MEASUREMENT | nginx_access_logs | InfluxDB measurement name for nginx logs. Optional, defaults to the example. |
| SEND_NGINX_LOGS | true | Set to `false` to disable nginx logs. Optional, defaults to `true`. |
| GEOIP2INFLUX_LOG_LEVEL | info | Sets the log level in geoip2influx.log. Use `debug` for verbose logging Optional, defaults to info. |
| GEOIP2INFLUX_LOG_PATH | /config/log/geoip2influx/geoip2influx.log | Optional. Defaults to example. |
| GEOIP_DB_PATH | /config/geoip2db/GeoLite2-City.mmdb | Optional. Defaults to example. |
| MAXMINDDB_LICENSE_KEY | xxxxxxx | Add your Maxmind licence key |
| MAXMINDDB_USER_ID | xxxxxxx| Add your Maxmind account id |

**InfluxDB v1.8.x values**

| Environment Variable | Example Value | Description |
| -------------------- | ------------- | ----------- |
| INFLUX_HOST | localhost | Host running InfluxDB. |
| INFLUX_HOST_PORT | 8086 | Optional, defaults to 8086. |
| INFLUX_DATABASE | geoip2influx | Optional, defaults to geoip2influx. |
| INFLUX_USER | root | Optional, defaults to root. |
| INFLUX_PASS | root | Optional, defaults to root. |
| INFLUX_RETENTION | 7d | Sets the retention for the database. Optional, defaults to example.|
| INFLUX_SHARD | 1d | Set the shard for the database. Optional, defaults to example. |

**InfluxDB v2.x values**

| Environment Variable | Example Value | Description |
| -------------------- | ------------- | ----------- |
| USE_INFLUXDB_V2 | true | Required if using InfluxDB2. Defaults to false |
| INFLUXDB_V2_TOKEN | secret-token | Required |
| INFLUXDB_V2_URL | http://localhost:8086 | Optional, defaults to http://localhost:8086 |
| INFLUXDB_V2_ORG | geoip2influx | Optional, defaults to geoip2influx. Will be created if not exists. |
| INFLUXDB_V2_BUCKET | geoip2influx | Optional, defaults to geoip2influx. Will be created if not exists. |
| INFLUXDB_V2_RETENTION | 604800 | Optional, defaults to 604800. 7 days in seconds |
| INFLUXDB_V2_DEBUG | false | Optional, defaults to false. Enables the debug mode for the influxdb-client package. |
| INFLUXDB_V2_BATCHING | true | Optional, defaults to false. Enables batch writing of data. |
| INFLUXDB_V2_BATCH_SIZE | 100 | Optional, defaults to 10. |
| INFLUXDB_V2_FLUSH_INTERVAL | 30000 | Optional, defaults to 15000. How often in milliseconds to write a batch |

### MaxMind Geolite2

Default download location is `/config/geoip2db/GeoLite2-City.mmdb`

Get your licence key here: https://www.maxmind.com/en/geolite2/signup

### InfluxDB 

#### InfluxDB v2.x and v1.8x is supported.

#### Note: The Grafana dashboard currently only supports InfluxDB v1.8.x

The InfluxDB database/bucket and retention rules will be created automatically with the name you choose.

```
-e INFLUX_DATABASE=geoip2influx or -e INFLUXDB_V2_BUCKET=geoip2influx
```

### Docker

```bash
docker create \
  --name=geoip2influx \
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=Europe/Oslo \
  -e INFLUX_HOST=<influxdb host> \
  -e INFLUX_HOST_PORT=<influxdb port> \
  -e MAXMINDDB_LICENSE_KEY=<license key>\
  -e MAXMINDDB_USER_ID=<account id>\
  -v /path/to/appdata/geoip2influx:/config \
  -v /path/to/nginx/accesslog/:/config/log/nginx/ \
  --restart unless-stopped \
  ghcr.io/gilbn/geoip2influx
```

### Docker compose

```yaml
version: "2.1"
services:
  geoip2influx:
    image: ghcr.io/gilbn/geoip2influx
    container_name: geoip2influx
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Europe/Oslo
      - INFLUX_HOST=<influxdb host>
      - INFLUX_HOST_PORT=<influxdb port>
      - MAXMINDDB_LICENSE_KEY=<license key>
      - MAXMINDDB_USER_ID=<account id>
    volumes:
      - /path/to/appdata/geoip2influx:/config
      - /path/to/nginx/accesslog/:/config/log/nginx/
    restart: unless-stopped
```

**InfluxDB2 examples**

```bash
docker create \
  --name=geoip2influx \
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=Europe/Oslo \
  -e INFLUXDB_V2_URL=<influxdb url> \
  -e INFLUXDB_V2_TOKEN=<influxdb token> \
  -e USE_INFLUXDB_V2=true \
  -e MAXMINDDB_LICENSE_KEY=<license key>\
  -e MAXMINDDB_USER_ID=<account id>\
  -v /path/to/appdata/geoip2influx:/config \
  -v /path/to/nginx/accesslog/:/config/log/nginx/ \
  --restart unless-stopped \
  ghcr.io/gilbn/geoip2influx
```

```yaml
version: "2.1"
services:
  geoip2influx:
    image: ghcr.io/gilbn/geoip2influx
    container_name: geoip2influx
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Europe/Oslo
      - INFLUXDB_V2_URL=<influxdb url>
      - INFLUXDB_V2_TOKEN=<influxdb token>
      - USE_INFLUXDB_V2=true
      - MAXMINDDB_LICENSE_KEY=<license key>
      - MAXMINDDB_USER_ID=<account id>
    volumes:
      - /path/to/appdata/geoip2influx:/config
      - /path/to/nginx/accesslog/:/config/log/nginx/
    restart: unless-stopped
```

***

## Grafana dashboard: 

Use [nginx_logs_geo_map.json](/nginx_logs_geo_map.json)

### Note

Currently only supports InfluxDB 1.8.x.

***

## Sending Nginx log metrics

Nginx needs to be compiled with the geoip2 module: https://github.com/leev/ngx_http_geoip2_module

1. Add the following to the http block in your `nginx.conf` file:

```nginx
geoip2 /config/geoip2db/GeoLite2-City.mmdb {
auto_reload 5m;
$geoip2_data_country_iso_code country iso_code;
$geoip2_data_city_name city names en;
}

log_format custom '$remote_addr - $remote_user [$time_local]'
           '"$request" $status $body_bytes_sent'
           '"$http_referer" $host "$http_user_agent"'
           '"$request_time" "$upstream_connect_time"'
           '"$geoip2_data_city_name" "$geoip2_data_country_iso_code"';
 ```
 
 2. Set the access log use the `custom` log format. 
 ```nginx
 access_log /config/log/nginx/access.log custom;
 ```

### Multiple log files

If you separate your nginx log files but want this script to parse all of them you can do the following:

As nginx can have multiple `access log` directives in a block, just add another one in the server block. 

**Example**

```nginx
	access_log /config/log/nginx/technicalramblings/access.log custom;
	access_log /config/log/nginx/access.log custom;
```
This will log the same lines to both files.

Then use the `/config/log/nginx/access.log` file in the `NGINX_LOG_PATH` variable. 

***

## Updates 

**18.08.24** - Rename env from USE_INFLUX_V2 to USE_INFLUXDB_V2.

**10.08.24** - Add support for InfluxDB2. 

**06.08.24** - Complete refactor of the python code. Deprecate the old geoip2influx.py file.

**28.07.24** - Refactor to alpine 3.20. New env required. MAXMINDDB_USER_ID. 

**21.06.20** - Added $host(domain) to the nginx log metrics. This will break your nginx logs parsing, as you need to update the custom log format.

**06.06.20** - Added influx retention policy to try and mitigate max-values-per-tag limit exceeded errors.

  * `-e INFLUX_RETENTION` Default 30d
  * `-e INFLUX_SHARD` Default 2d
  * It will only add the retention policy if the database doesn't exist.

**30.05.20** - Added logging. Use `-e GEOIP2INFLUX_LOG_LEVEL` to set the log level.

**15.05.20** - Removed `GEOIP2_KEY` and `GEOIP_DB_PATH`variables. With commit https://github.com/linuxserver/docker-letsencrypt/commit/75b9685fdb3ec6edda590300f289b0e75dd9efd0 the letsencrypt container now natively supports downloading and updating(weekly) the GeoLite2-City database!

***

Adapted source: https://github.com/ratibor78/geostat
