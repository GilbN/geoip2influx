FROM lsiobase/alpine:3.20
LABEL maintainer="GilbN"

WORKDIR /geoip2influx

# Copy the requirements.txt and run.py files
COPY requirements.txt run.py ./

# Copy the entire geoip2influx directory
COPY /geoip2influx /geoip2influx/

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
