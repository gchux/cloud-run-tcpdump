# syntax=docker/dockerfile:1.4

ARG LIBPCAP_VERSION='1.10.5'
ARG TCPDUMP_VERSION='4.99.5'

FROM pcap-base:libpcap-v${LIBPCAP_VERSION}_tcpdump-v${TCPDUMP_VERSION} AS base

FROM --platform=linux/amd64 ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ARG GCSFUSE_VERSION='2.1.0'

WORKDIR /app

USER 0:0

RUN apt-get -qq update  > /dev/null \
    && apt-get -qq -y install tzdata curl jq fuse > /dev/null \
    && apt-get -qq clean > /dev/null

COPY --from=base /dist/bin/ /usr/bin/
COPY --from=base /dist/lib/ /lib/x86_64-linux-gnu/

RUN ldconfig -v

RUN curl -o /gcsfuse.deb -L \
    https://github.com/GoogleCloudPlatform/gcsfuse/releases/download/v${GCSFUSE_VERSION}/gcsfuse_${GCSFUSE_VERSION}_amd64.deb \
    && dpkg -i --force-all /gcsfuse.deb && rm -vf /gcsfuse.deb
