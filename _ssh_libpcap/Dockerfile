ARG SSH_SERVER_VERSION=amd64-9.7_p1-r4-ls174

FROM --platform=linux/amd64 lscr.io/linuxserver/openssh-server:${SSH_SERVER_VERSION}

ARG DEBIAN_FRONTEND=noninteractive

ARG LIBPCAP_VERSION='1.4.0'
ARG LIBPCAP_DL_FNAME='libpcap-1.4.0.tar.gz'

ARG TCPDUMP_VERSION='4.9.3'
ARG TCPDUMP_DL_FNAME='tcpdump-4.9.3.tar.gz'
ARG TCPDUMP_BIN_DIR='bin'

ARG WEB_PORT="8022"
ARG SSH_USER="root"
ARG SSH_PASS="pass"
ARG PASSWORD_ACCESS="true"
ARG SUDO_ACCESS="true"

ENV PUID=0
ENV PGID=0

USER 0:0

RUN apk update && apk add --update --quiet --no-progress --no-cache \
  linux-headers alpine-sdk build-base g++ make musl-dev go strace \
  python3 py3-pip gcc flex bison musl-dev git neovim curl wget tmux

WORKDIR /app

RUN wget -q -nv https://www.tcpdump.org/release/${LIBPCAP_DL_FNAME} && mkdir -p /app/libpcap/ \
  && tar -xvf libpcap-${LIBPCAP_VERSION}.tar.*z -C /app/libpcap --strip-components=1

WORKDIR /app/libpcap

RUN ./configure && make && make install

WORKDIR /app

RUN wget -q -nv https://www.tcpdump.org/release/${TCPDUMP_DL_FNAME} && mkdir -p /app/tcpdump/ \
  && tar -xvf tcpdump-${TCPDUMP_VERSION}.tar.*z -C /app/tcpdump/ --strip-components=1

WORKDIR /app/tcpdump

RUN ldconfig -v / \
  && ./configure && make && make install \
  && ldconfig -v /

RUN python -m pip config --user set global.progress_bar off \
  && python -m pip install --break-system-packages --no-cache-dir webssh \
  && echo "root:pass" | chpasswd \
  && sed --in-place '/PermitRootLogin/d' /etc/ssh/sshd_config \
  && sed --in-place '/AllowTcpForwarding/d' /etc/ssh/sshd_config \
  && echo -e '\nPermitRootLogin yes' >> /etc/ssh/sshd_config \
  && echo -e '\nAllowTcpForwarding yes' >> /etc/ssh/sshd_config

WORKDIR /

RUN git clone --depth 1 --branch master https://github.com/google/gopacket.git

WORKDIR /gopacket

RUN go mod tidy && go mod download \
  && go build -a -v -o /pcapdump ./examples/pcapdump/main.go

WORKDIR /

COPY ./init_wssh /init_wssh

ENV USER_NAME=${SSH_USER}
ENV USER_PASSWORD=${SSH_PASS}
ENV PASSWORD_ACCESS=${PASSWORD_ACCESS}
ENV SUDO_ACCESS=${SUDO_ACCESS}
ENV LOG_STDOUT=true
ENV HTTP_PORT=${WEB_PORT}

RUN echo "${WEB_PORT}" > /http.port

EXPOSE ${WEB_PORT}/tcp

CMD ["exec", "env", "/init_wssh"]
