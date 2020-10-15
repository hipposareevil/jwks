FROM openjdk:8-jdk-alpine

# Basics
RUN apk --no-cache add curl bash

ARG JAR_FILE
COPY target/${JAR_FILE} app.jar

EXPOSE 8080

RUN mkdir /kms
COPY resources/ /kms/

COPY entrypoint.sh docker-run.sh
ENTRYPOINT ["/bin/bash","/docker-run.sh"]
