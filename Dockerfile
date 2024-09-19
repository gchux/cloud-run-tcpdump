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

FROM --platform=linux/amd64 pcap-sidecar:latest

ARG DEBIAN_FRONTEND=noninteractive
ARG GCSFUSE_VERSION='2.1.0'

LABEL org.opencontainers.image.description="Cloud Run PCAP sidecar"

USER 0:0

RUN apt-get -qq update > /dev/null \
    && apt-get install -qq -y tzdata curl jq fuse \
    && apt-get -qq clean > /dev/null

RUN curl -o /gcsfuse.deb -L \
    https://github.com/GoogleCloudPlatform/gcsfuse/releases/download/v${GCSFUSE_VERSION}/gcsfuse_${GCSFUSE_VERSION}_amd64.deb \
    && dpkg -i --force-all /gcsfuse.deb && rm -vf /gcsfuse.deb

COPY ./bin /bin
COPY ./scripts /scripts
COPY ./tcpdump.conf /tcpdump.conf
COPY ./scripts/init /init

ENTRYPOINT ["/init"]
