# syntax=docker/dockerfile:1.4

FROM golang:1.22.2-bookworm AS build

WORKDIR /app

COPY ./go.mod go.mod
COPY ./go.sum go.sum
COPY ./main.go main.go

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN go build -v -o /app/pcap_fsn

FROM scratch AS releaser
COPY --link --from=build /app/pcap_fsn /
