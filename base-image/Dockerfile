FROM --platform=linux/amd64 ubuntu:22.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG LIBPCAP_VERSION=1.9.1

WORKDIR /app

USER 0:0

RUN apt-get -qq update  > /dev/null \
    && apt-get -qq -y install build-essential flex bison wget \
    && apt-get -qq clean > /dev/null

RUN wget https://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz \
    && tar -xzvf libpcap-${LIBPCAP_VERSION}.tar.gz

RUN cd libpcap-${LIBPCAP_VERSION} \
    && mkdir /app/libpcap-${LIBPCAP_VERSION}/dist/ \
    && ./configure --prefix=/app/libpcap-${LIBPCAP_VERSION}/dist/ \
    && make && make install \
    && ls -lR /app/libpcap-${LIBPCAP_VERSION}/dist/

# FROM --platform=linux/amd64 ubuntu:22.04 AS builder

