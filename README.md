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

### For the linuxserver/letsencrypt docker mod, click here : https://github.com/gilbN/lsio-docker-mods/tree/master/letsencrypt/geoip2-nginx-stats

***

## Usage

### Enviroment variables:

These are the **default** values for all envs. 
Add the ones that differ on your system. 

| Environment Variable | Example Value | Description |
| -------------------- | ------------- | ----------- |
| NGINX_LOG_PATH | /config/log/nginx/access.log | Container path for Nginx logfile , defaults to the example. |
| INFLUX_HOST | localhost | Host running InfluxDB. |
| INFLUX_HOST_PORT | 8086 | Optional, defaults to 8086. |
| INFLUX_DATABASE | geoip2influx | Optional, defaults to geoip2influx. |
| INFLUX_USER | root | Optional, defaults to root. |
| INFLUX_PASS | root | Optional, defaults to root. |
| GEO_MEASUREMENT | geoip2influx | InfluxDB measurement name for geohashes. Optional, defaults to the example. |
| LOG_MEASUREMENT | nginx_access_logs | InfluxDB measurement name for nginx logs. Optional, defaults to the example. |
| SEND_NGINX_LOGS | true | Set to `false` to disable nginx logs. Optional, defaults to `true`. |
| GEOIP2INFLUX_LOG_LEVEL | info | Sets the log level in geoip2influx.log. Use `debug` for verbose logging Optional, defaults to info. |
| INFLUX_RETENTION | 30d | Sets the retention for the database. Optional, defaults to example.|
| INFLUX_SHARD | 2d | Set the shard for the database. Optional, defaults to example. |
| MAXMINDDB_LICENSE_KEY | xxxxxxx | Add your Maxmind licence key |


### MaxMind Geolite2

Default download location is `/config/geoip2db/GeoLite2-City.mmdb`

Get your licence key here: https://www.maxmind.com/en/geolite2/signup

### InfluxDB 

The InfluxDB database will be created automatically with the name you choose.

```
-e INFLUX_DATABASE=geoip2influx 
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
  -v /path/to/appdata/geoip2influx:/config \
  -v /path/to/nginx/accesslog/:/config/log/nginx/ \
  --restart unless-stopped \
  gilbn/geoip2influx
```

### Docker compose

```yaml
version: "2.1"
services:
  geoip2influx:
    image: gilbn/geoip2influx
    container_name: geoip2influx
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Europe/Oslo
      - INFLUX_HOST=<influxdb host>
      - INFLUX_HOST_PORT=<influxdb port>
      - MAXMINDDB_LICENSE_KEY=<license key>
    volumes:
      - /path/to/appdata/geoip2influx:/config
      - /path/to/nginx/accesslog/:/config/log/nginx/
    restart: unless-stopped
```

***

## Grafana dashboard: 
### [Grafana Dashboard Link](https://grafana.com/grafana/dashboards/12268/)

***

## Sending Nginx log metrics

Nginx needs to be compiled with the geoip2 module: https://github.com/leev/ngx_http_geoip2_module

1. Add the following to the http block in your `nginx.conf` file:

```nginx
geoip2 /config/geoip2db/GeoLite2-City.mmdb {
auto_reload 5m;
$geoip2_data_country_code country iso_code;
$geoip2_data_city_name city names en;
}

log_format custom '$remote_addr - $remote_user [$time_local]'
           '"$request" $status $body_bytes_sent'
           '"$http_referer" $host "$http_user_agent"'
           '"$request_time" "$upstream_connect_time"'
           '"$geoip2_data_city_name" "$geoip2_data_country_code"';
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

**21.06.20** - Added $host(domain) to the nginx log metrics. This will break your nginx logs parsing, as you need to update the custom log format.

**06.06.20** - Added influx retention policy to try and mitigate max-values-per-tag limit exceeded errors.

  * `-e INFLUX_RETENTION` Default 30d
  * `-e INFLUX_SHARD` Default 2d
  * It will only add the retention policy if the database doesn't exist.

**30.05.20** - Added logging. Use `-e GEOIP2INFLUX_LOG_LEVEL` to set the log level.

**15.05.20** - Removed `GEOIP2_KEY` and `GEOIP_DB_PATH`variables. With commit https://github.com/linuxserver/docker-letsencrypt/commit/75b9685fdb3ec6edda590300f289b0e75dd9efd0 the letsencrypt container now natively supports downloading and updating(weekly) the GeoLite2-City database!

***

Adapted source: https://github.com/ratibor78/geostat
