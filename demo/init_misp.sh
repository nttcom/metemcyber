#!/bin/sh -ex
git clone https://github.com/harvard-itsecurity/docker-misp.git

docker build \
--rm=true --force-rm=true \
--build-arg MYSQL_MISP_PASSWORD=a9564ebc3289b7a14551baf8ad5ec60a \
--build-arg POSTFIX_RELAY_HOST=localhost \
--build-arg MISP_FQDN=localhost \
--build-arg MISP_EMAIL=admin@localhost \
--build-arg MISP_GPG_PASSWORD=XuJBao5Q2bps89LWFqWkKgDZwAFpNHvc \
-t harvarditsecurity/misp docker-misp/container

if [ ! -e misp-db ]; then
    mkdir misp-db
else
    rm -rf misp-db
    mkdir misp-db
fi

mkdir -p misp-db
docker run -it --rm \
-v misp-db:/var/lib/mysql \
harvarditsecurity/misp /init-db

docker run -it -d \
--name some-misp \
-p 443:443 \
-p 80:80 \
-p 3306:3306 \
-v misp-db:/var/lib/mysql \
harvarditsecurity/misp