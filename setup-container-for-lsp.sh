#!/bin/sh
# I hard-coded it to work for me in the Dockerfile but this may make it work for you
docker exec -i telefork mkdir -p $(dirname $PWD)
docker exec -i telefork ln -sf /usr/src/telefork $PWD
