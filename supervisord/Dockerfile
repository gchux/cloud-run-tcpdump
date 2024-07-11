# syntax=docker/dockerfile:1.4

FROM curlimages/curl AS provider

WORKDIR /app

RUN curl -s -L -o supervisord.zip https://github.com/ochinchina/supervisord/archive/refs/heads/master.zip \
    && unzip supervisord.zip -d ./tmp && mv ./tmp/*-master/* . && rm -rvf ./supervisord.zip ./tmp

FROM golang:1.22.4-bookworm AS builder

WORKDIR /app

COPY --from=provider /app/ .

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN go generate && go build -v -a -tags release -ldflags '-extldflags "-static"' -o supervisord

FROM scratch AS releaser
COPY --link --from=builder /app/supervisord /
