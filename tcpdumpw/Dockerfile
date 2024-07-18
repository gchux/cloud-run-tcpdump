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


FROM --platform=linux/amd64 golang:1.22.4-bookworm AS build

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
