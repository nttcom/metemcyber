#!/bin/sh -x
docker stop some-misp
docker rm some-misp
rm -rf misp-db
rm -rf docker-misp
docker rmi harvarditsecurity/misp