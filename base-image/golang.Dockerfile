# syntax=docker/dockerfile:1.4

FROM --platform=linux/amd64 golang:1.22.4-bookworm AS libpcap

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

FROM --platform=linux/amd64 golang:1.22.4-bookworm AS tcpdump

ARG DEBIAN_FRONTEND=noninteractive
ARG LIBPCAP_VERSION=1.9.1
ARG TCPDUMP_VERSION=4.99.5

WORKDIR /app

USER 0:0

COPY --from=libpcap /app/libpcap-${LIBPCAP_VERSION}/dist/bin/ /bin/
COPY --from=libpcap /app/libpcap-${LIBPCAP_VERSION}/dist/lib/ /lib/x86_64-linux-gnu/
COPY --from=libpcap /app/libpcap-${LIBPCAP_VERSION}/dist/include/ /usr/include/

RUN ldconfig -v

RUN apt-get -qq update  > /dev/null \
    && apt-get -qq -y install build-essential wget \
    && apt-get -qq clean > /dev/null

RUN wget https://www.tcpdump.org/release/tcpdump-${TCPDUMP_VERSION}.tar.xz \
    && tar -xvf tcpdump-${TCPDUMP_VERSION}.tar.xz

RUN cd tcpdump-${TCPDUMP_VERSION} \
    && mkdir /app/tcpdump-${TCPDUMP_VERSION}/dist/ \
    && ./configure --prefix=/app/tcpdump-${TCPDUMP_VERSION}/dist/ \
    && make && make install \
    && ls -lR /app/tcpdump-${TCPDUMP_VERSION}/dist/

FROM --platform=linux/amd64 golang:1.22.4-bookworm

ARG DEBIAN_FRONTEND=noninteractive
ARG LIBPCAP_VERSION=1.9.1
ARG TCPDUMP_VERSION=4.99.5

USER 0:0

COPY --from=libpcap /app/libpcap-${LIBPCAP_VERSION}/dist/bin/ /bin/
COPY --from=tcpdump /app/tcpdump-${TCPDUMP_VERSION}/dist/bin/ /bin/
COPY --from=libpcap /app/libpcap-${LIBPCAP_VERSION}/dist/lib/ /lib/x86_64-linux-gnu/
COPY --from=libpcap /app/libpcap-${LIBPCAP_VERSION}/dist/include/ /usr/include/

RUN ldconfig -v
