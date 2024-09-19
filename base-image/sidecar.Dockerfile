# syntax=docker/dockerfile:1.4

FROM --platform=linux/amd64 ubuntu:22.04

USER 0:0

COPY --from=pcap-base:latest /dist/bin/ /usr/bin/
COPY --from=pcap-base:latest /dist/bin/ /usr/bin/
COPY --from=pcap-base:latest /dist/lib/ /lib/x86_64-linux-gnu/

RUN ldconfig -v
