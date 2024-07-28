FROM lsiobase/alpine:3.20
LABEL maintainer="GilbN"

WORKDIR /geoip2influx
COPY requirements.txt geoip2influx.py /geoip2influx/
RUN \
echo " ## Installing packages ## " && \
apk add --no-cache --virtual=build-dependencies \
    python3-dev \
    py3-pip \
    logrotate \
    libmaxminddb && \
echo "**** install packages ****" && \
apk add --no-cache \
    python3 && \
echo " ## Installing python modules ## " && \
python3 -m venv /lsiopy && \
pip3 install --no-cache-dir -r requirements.txt
COPY root/ /
