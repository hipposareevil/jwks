#!/bin/bash

mvn install

docker build --build-arg JAR_FILE=jwks-0.0.1.jar -t hipposareevil/jwks .
