# syntax=docker/dockerfile:1.4

ARG LIBPCAP_VERSION='1.10.5'
ARG TCPDUMP_VERSION='4.99.5'

FROM pcap-base:libpcap-v${LIBPCAP_VERSION}_tcpdump-v${TCPDUMP_VERSION} AS base

FROM --platform=linux/amd64 golang:1.22.4-bookworm

USER 0:0

COPY --from=base /dist/bin/ /usr/bin/
COPY --from=base /dist/lib/ /lib/x86_64-linux-gnu/
COPY --from=base /dist/include/ /usr/include/

RUN ldconfig -v
