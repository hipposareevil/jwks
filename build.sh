#!/bin/bash

set -e

echo "[install]"
mvn install

echo "[copy certs]"
mkdir -p /tmp/kms; cp -r resources/dktool_repo /tmp/kms

echo "[make docker image]"
docker build --build-arg JAR_FILE=jwks-0.0.1.jar -t hipposareevil/jwks .

