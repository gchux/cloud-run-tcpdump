# syntax=docker/dockerfile:1.4
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG LIBPCAP_VERSION='1.10.5'
ARG TCPDUMP_VERSION='4.99.5'

FROM --platform=linux/amd64 pcap-golang:libpcap-v${LIBPCAP_VERSION}_tcpdump-v${TCPDUMP_VERSION} AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG BIN_NAME='tcpdumpw'

WORKDIR /app

RUN go install mvdan.cc/gofumpt@latest

COPY ./go.mod go.mod
COPY ./go.sum go.sum
COPY ./main.go main.go

ENV GOOS=linux
ENV GOARCH=amd64

RUN gofumpt -l -w ./main.go
RUN go mod tidy -compat=1.22.4
RUN go mod download
RUN go build -a -v -o /app/bin/${BIN_NAME} main.go

FROM scratch AS releaser
COPY --link --from=builder /app/bin/${BIN_NAME} /
