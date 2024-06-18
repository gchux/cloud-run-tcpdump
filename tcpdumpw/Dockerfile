# syntax=docker/dockerfile:1.4

FROM golang:1.22.4-bookworm AS build

ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /app

RUN apt-get -qq update > /dev/null && apt-get install -qq -y libpcap-dev && apt-get -qq clean > /dev/null

COPY ./go.mod go.mod
COPY ./go.sum go.sum
COPY ./main.go main.go

ENV GOOS=linux
ENV GOARCH=amd64

RUN go build -a -v -o /app/tcpdumpw main.go

FROM scratch AS releaser
COPY --link --from=build /app/tcpdumpw /
