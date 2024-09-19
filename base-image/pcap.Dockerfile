# syntax=docker/dockerfile:1.4

FROM --platform=linux/amd64 debian:bookworm-slim AS libpcap

ARG DEBIAN_FRONTEND=noninteractive
ARG LIBPCAP_VERSION=1.9.1

WORKDIR /app

USER 0:0

# see: https://github.com/the-tcpdump-group/libpcap/blob/master/INSTALL.md

RUN apt-get -qq update  > /dev/null \
    && apt-get -qq -y install build-essential flex bison wget > /dev/null \
    && apt-get -qq clean > /dev/null

RUN wget https://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz \
    && mkdir -p /app/libpcap/ \
    && tar -xvf libpcap-${LIBPCAP_VERSION}.tar.gz -C /app/libpcap --strip-components=1

RUN cd /app/libpcap \
    && mkdir -p /app/libpcap/dist/ \
    && ./configure --prefix=/app/libpcap/dist/ \
    && make && make install \
    && ls -lR /app/libpcap/dist/

FROM --platform=linux/amd64 debian:bookworm-slim AS tcpdump

ARG DEBIAN_FRONTEND=noninteractive
ARG TCPDUMP_VERSION=4.99.5

WORKDIR /app

USER 0:0

RUN apt-get -qq update  > /dev/null \
    && apt-get -qq -y install build-essential wget > /dev/null \
    && apt-get -qq clean > /dev/null

# same as `apt-get install libpcap-dev`: install shared objects and header files
COPY --from=libpcap /app/libpcap/dist/bin/ /usr/bin/
COPY --from=libpcap /app/libpcap/dist/lib/ /lib/x86_64-linux-gnu/
COPY --from=libpcap /app/libpcap/dist/include/ /usr/include/

# see: https://github.com/the-tcpdump-group/tcpdump/blob/master/INSTALL.md#on-unxes
RUN wget https://www.tcpdump.org/release/tcpdump-${TCPDUMP_VERSION}.tar.xz \
    && mkdir -p /app/tcpdump/ \
    && tar -xvf tcpdump-${TCPDUMP_VERSION}.tar.xz -C /app/tcpdump/ --strip-components=1

RUN ldconfig -v \
    && cd /app/tcpdump \
    && mkdir -p /app/tcpdump/dist/ \
    && ./configure --prefix=/app/tcpdump/dist/ \
    && make && make install \
    && ls -lR /app/tcpdump/dist/

FROM --platform=linux/amd64 debian:bookworm-slim

USER 0:0

COPY --from=tcpdump /app/tcpdump/dist/bin/ /usr/bin/
COPY --from=libpcap /app/libpcap/dist/bin/ /usr/bin/
COPY --from=libpcap /app/libpcap/dist/lib/ /lib/x86_64-linux-gnu/
COPY --from=libpcap /app/libpcap/dist/include/ /usr/include/

COPY --from=tcpdump /app/tcpdump/dist/bin/ /dist/bin/
COPY --from=libpcap /app/libpcap/dist/bin/ /dist/bin/
COPY --from=libpcap /app/libpcap/dist/lib/ /dist/lib/
COPY --from=libpcap /app/libpcap/dist/include/ /dist/include/

RUN ldconfig -v
