#! /usr/bin/env python3

from os.path import exists, isfile
from os import environ as env, stat
from platform import uname
from re import compile, match, search, IGNORECASE
from sys import path, exit
from time import sleep, time
from datetime import datetime
import logging

from geoip2.database import Reader
from geohash2 import encode
from influxdb import InfluxDBClient
from requests.exceptions import ConnectionError
from influxdb.exceptions import InfluxDBServerError, InfluxDBClientError
from IPy import IP as ipadd


# Getting params from envs
geoip_db_path = '/config/geoip2db/GeoLite2-City.mmdb'
log_path = env.get('NGINX_LOG_PATH', '/config/log/nginx/access.log')
influxdb_host = env.get('INFLUX_HOST', 'localhost')
influxdb_port = env.get('INFLUX_HOST_PORT', '8086')
influxdb_database = env.get('INFLUX_DATABASE', 'geoip2influx')
influxdb_user = env.get('INFLUX_USER', 'root')
influxdb_user_pass = env.get('INFLUX_PASS', 'root')
influxdb_retention = env.get('INFLUX_RETENTION','7d')
influxdb_shard = env.get('INFLUX_SHARD', '1d')
geo_measurement = env.get('GEO_MEASUREMENT', 'geoip2influx')
log_measurement = env.get('LOG_MEASUREMENT', 'nginx_access_logs')
send_nginx_logs = env.get('SEND_NGINX_LOGS','true')
log_level = env.get('GEOIP2INFLUX_LOG_LEVEL', 'info').upper()
g2i_log_path = env.get('GEOIP2INFLUX_LOG_PATH','/config/log/geoip2influx/geoip2influx.log')

# Logging
logging.basicConfig(level=log_level,format='%(asctime)s :: %(levelname)s :: %(message)s',datefmt='%d/%b/%Y %H:%M:%S',filename=g2i_log_path)

def regex_tester(log_path, N):
    time_out = time() + 60
    re_ipv4 = compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    re_ipv6 = compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))') # NOQA
    while True:
        assert N >= 0
        pos = N + 1
        lines = []
        with open(log_path) as f:
            while len(lines) <= N:
                try:
                    f.seek(-pos, 2)
                except IOError:
                    f.seek(0)
                    break
                finally:
                    lines = list(f)
                pos *= 2
        log_lines = lines[-N:]
        for line in log_lines:
            if re_ipv4.match(line):
                regex = compile(r'(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4}))\](["](?P<method>.+)) (?P<referrer>.+) ((?P<http_version>HTTP\/[1-3]\.[0-9])["]) (?P<status_code>\d{3}) (?P<bytes_sent>\d{1,99})(["](?P<url>(\-)|(.+))["]) (?P<host>.+) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["])(["](?P<city>.+)["]) (["](?P<country_code>.+)["])', IGNORECASE) # NOQA
                if regex.match(line):
                    logging.debug(f'Regex is matching {log_path} continuing...')
                    return True
            if re_ipv6.match(line):
                regex = compile(r'(?P<ipaddress>(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4}))\](["](?P<method>.+)) (?P<referrer>.+) ((?P<http_version>HTTP\/[1-3]\.[0-9])["]) (?P<status_code>\d{3}) (?P<bytes_sent>\d{1,99})(["](?P<url>(\-)|(.+))["]) (?P<host>.+) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["])(["](?P<city>.+)["]) (["](?P<country_code>.+)["])', IGNORECASE) # NOQA
                if regex.match(line):
                    logging.debug(f'Regex is matching {log_path} continuing...')
                    return True
            else:
                logging.debug(f'Testing regex on: {log_path}')
                sleep(2)
        if time() > time_out:
            logging.warning(f'Failed to match regex on: {log_path}')
            break


def file_exists(log_path,geoip_db_path):
    time_out = time() + 30
    while True:
        file_list = [log_path, geoip_db_path]
        if not exists(log_path):
            logging.warning((f'File: {log_path} not found...'))
            sleep(1)
        if not exists(geoip_db_path):
            logging.warning((f'File: {geoip_db_path} not found...'))
            sleep(1)
        if all([isfile(f) for f in file_list]):
            for f in file_list:
                logging.debug(f'Found: {f}')
            return True
        if time() > time_out:
            if not exists(geoip_db_path) and not exists(log_path):
                logging.critical(f"Can't find: {geoip_db_path} or {log_path} exiting!")
                break
            elif not exists(geoip_db_path):
                logging.critical(f"Can't find: {geoip_db_path}, exiting!")
                break
            elif not exists(log_path):
                logging.critical(f"Can't find: {log_path}, exiting!")
                break


def logparse(
        log_path, influxdb_host, influxdb_port, influxdb_database, influxdb_user, influxdb_user_pass, influxdb_retention,
        influxdb_shard, geo_measurement, log_measurement, send_nginx_logs, geoip_db_path, inode):
    # Preparing variables and params
    ips = {}
    geohash_fields = {}
    geohash_tags = {}
    log_data_fields = {}
    log_data_tags = {}
    nginx_log = {}
    hostname = uname()[1]
    client = InfluxDBClient(
        host=influxdb_host, port=influxdb_port, username=influxdb_user, password=influxdb_user_pass, database=influxdb_database)

    try:
        logging.debug('Testing InfluxDB connection')
        version = client.request('ping', expected_response_code=204).headers['X-Influxdb-Version']
        logging.debug(f'Influxdb version: {version}')
    except ConnectionError as e:
        logging.critical('Error testing connection to InfluxDB. Please check your url/hostname.\n'
                         f'Error: {e}'
                        )
        exit(1)

    try:
        databases = [db['name'] for db in client.get_list_database()]
        if influxdb_database in databases:    
            logging.debug(f'Found database: {influxdb_database}')
    except InfluxDBClientError as e:
        logging.critical('Error getting database list! Please check your InfluxDB configuration.\n'
                         f'Error: {e}'
                        )
        exit(1)

    if influxdb_database not in databases:
        logging.info(f'Creating database: {influxdb_database}')
        client.create_database(influxdb_database)

        retention_policies = [policy['name'] for policy in client.get_list_retention_policies(database=influxdb_database)]
        if f'{influxdb_database} {influxdb_retention}-{influxdb_shard}' not in retention_policies:
            logging.info(f'Creating {influxdb_database} retention policy ({influxdb_retention}-{influxdb_shard})')
            client.create_retention_policy(name=f'{influxdb_database} {influxdb_retention}-{influxdb_shard}', duration=influxdb_retention, replication='1',
                                                database=influxdb_database, default=True, shard_duration=influxdb_shard)

    re_ipv4 = compile(r'(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4}))\](["](?P<method>.+)) (?P<referrer>.+) ((?P<http_version>HTTP\/[1-3]\.[0-9])["]) (?P<status_code>\d{3}) (?P<bytes_sent>\d{1,99})(["](?P<url>(\-)|(.+))["]) (?P<host>.+) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["])(["](?P<city>.+)["]) (["](?P<country_code>.+)["])', IGNORECASE) # NOQA
    re_ipv6 = compile(r'(?P<ipaddress>(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))) - (?P<remote_user>.+) \[(?P<dateandtime>\d{2}\/[A-Z]{1}[a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2} ((\+|\-)\d{4}))\](["](?P<method>.+)) (?P<referrer>.+) ((?P<http_version>HTTP\/[1-3]\.[0-9])["]) (?P<status_code>\d{3}) (?P<bytes_sent>\d{1,99})(["](?P<url>(\-)|(.+))["]) (?P<host>.+) (["](?P<user_agent>.+)["])(["](?P<request_time>.+)["]) (["](?P<connect_time>.+)["])(["](?P<city>.+)["]) (["](?P<country_code>.+)["])', IGNORECASE) # NOQA

    gi = Reader(geoip_db_path)

    if send_nginx_logs in ('true', 'True'):
        send_logs = True
    else:
        send_logs = False
        re_ipv4 = compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        re_ipv6 = compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))') # NOQA
        logging.info('SEND_NGINX_LOGS set to false')
        pass
    if not regex_tester(log_path,3):
        if send_logs:
            re_ipv4 = compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            re_ipv6 = compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))') # NOQA
            send_logs = False
            logging.warning('NGINX log metrics disabled! Double check your NGINX custom log format..')

    # Main loop to parse access.log file in tailf style with sending metrics.
    with open(log_path, 'r') as log_file:
        logging.info('Starting log parsing')
        str_results = stat(log_path)
        st_size = str_results[6]
        log_file.seek(st_size)
        while True:
            geo_metrics = []
            log_metrics = []
            where = log_file.tell()
            line = log_file.readline()
            inodenew = stat(log_path).st_ino
            if inode != inodenew:
                break
            if not line:
                sleep(1)
                log_file.seek(where)
            else:
                if re_ipv4.match(line):
                    m = re_ipv4.match(line)
                    ip = m.group(1)
                    log = re_ipv4
                elif re_ipv6.match(line):
                    m = re_ipv6.match(line)
                    ip = m.group(1)
                    log = re_ipv6
                else:
                    logging.warning('Failed to match regex that previously matched!? Skipping this line!\n'
                                    'Please share the log line below on Discord or Github!\n' 
                                    f'Line: {line}'
                                   )
                    continue
                if ipadd(ip).iptype() == 'PUBLIC' and ip:
                    info = gi.city(ip)
                    if info is not None:
                        geohash = encode(info.location.latitude, info.location.longitude)
                        geohash_fields['count'] = 1
                        geohash_tags['geohash'] = geohash
                        geohash_tags['ip'] = ip
                        geohash_tags['host'] = hostname
                        geohash_tags['country_code'] = info.country.iso_code
                        geohash_tags['country_name'] = info.country.name
                        geohash_tags['state'] = info.subdivisions.most_specific.name
                        geohash_tags['state_code'] = info.subdivisions.most_specific.iso_code
                        geohash_tags['city'] = info.city.name
                        geohash_tags['postal_code'] = info.postal.code
                        geohash_tags['latitude'] = info.location.latitude
                        geohash_tags['longitude'] = info.location.longitude
                        ips['tags'] = geohash_tags
                        ips['fields'] = geohash_fields
                        ips['measurement'] = geo_measurement
                        geo_metrics.append(ips)
                        logging.debug(f'Geo metrics: {geo_metrics}')
                        try:
                            client.write_points(geo_metrics)
                        except (InfluxDBServerError, ConnectionError) as e:
                            logging.error('Error writing data to InfluxDB! Check your database!\n'
                                          f'Error: {e}'
                                         )

                if send_logs:
                    data = search(log, line)
                    if ipadd(ip).iptype() == 'PUBLIC' and ip:
                        info = gi.city(ip)
                        if info is not None:
                            datadict = data.groupdict()
                            log_data_fields['count'] = 1
                            log_data_fields['bytes_sent'] = int(datadict['bytes_sent'])
                            log_data_fields['request_time'] = float(datadict['request_time'])
                            if datadict['connect_time'] == '-':
                                log_data_fields['connect_time'] = 0.0
                            else:
                                log_data_fields['connect_time'] = float(datadict['connect_time'])
                            log_data_tags['ip'] = datadict['ipaddress']
                            log_data_tags['datetime'] = datetime.strptime(datadict['dateandtime'], '%d/%b/%Y:%H:%M:%S %z')
                            log_data_tags['remote_user'] = datadict['remote_user']
                            log_data_tags['method'] = datadict['method']
                            log_data_tags['referrer'] = datadict['referrer']
                            log_data_tags['host'] = datadict['host']
                            log_data_tags['http_version'] = datadict['http_version']
                            log_data_tags['status_code'] = datadict['status_code']
                            log_data_tags['bytes_sent'] = datadict['bytes_sent']
                            log_data_tags['url'] = datadict['url']
                            log_data_tags['user_agent'] = datadict['user_agent']
                            log_data_tags['request_time'] = datadict['request_time']
                            log_data_tags['connect_time'] = datadict['connect_time']
                            log_data_tags['city'] = datadict['city']
                            log_data_tags['country_code'] = datadict['country_code']
                            log_data_tags['country_name'] = info.country.name
                            nginx_log['tags'] = log_data_tags
                            nginx_log['fields'] = log_data_fields
                            nginx_log['measurement'] = log_measurement
                            log_metrics.append(nginx_log)
                            logging.debug(f'NGINX log metrics: {log_metrics}')
                            try:
                                client.write_points(log_metrics)
                            except (InfluxDBServerError, InfluxDBClientError, ConnectionError) as e:
                                logging.error('Error writing data to InfluxDB! Check your database!\n'
                                            f'Error: {e}'
                                            )


def main():
    logging.info('Starting geoip2influx..')

    logging.debug('Variables set:' +
    f'\n geoip_db_path             :: {geoip_db_path}' +
    f'\n -e LOG_PATH               :: {log_path}' +
    f'\n -e INFLUX_HOST            :: {influxdb_host}' +
    f'\n -e INFLUX_HOST_PORT       :: {influxdb_port}' +
    f'\n -e INFLUX_DATABASE        :: {influxdb_database}' +
    f'\n -e INFLUX_RETENTION       :: {influxdb_retention}' +
    f'\n -e INFLUX_SHARD           :: {influxdb_shard}' +
    f'\n -e INFLUX_USER            :: {influxdb_user}' +
    f'\n -e INFLUX_PASS            :: {influxdb_user_pass}' +
    f'\n -e GEO_MEASUREMENT        :: {geo_measurement}' +
    f'\n -e LOG_MEASUREMENT        :: {log_measurement}' +
    f'\n -e SEND_NGINX_LOGS        :: {send_nginx_logs}' +
    f'\n -e GEOIP2INFLUX_LOG_LEVEL :: {log_level}' 
    )
    # Parsing log file and sending metrics to Influxdb
    while file_exists(log_path,geoip_db_path):
        # Get inode from log file
        inode = stat(log_path).st_ino
        # Run main loop and grep a log file
        logparse(
            log_path, influxdb_host, influxdb_port, influxdb_database, influxdb_user, influxdb_user_pass,
            influxdb_retention, influxdb_shard, geo_measurement, log_measurement, send_nginx_logs, geoip_db_path, inode) # NOQA

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        exit(0)
