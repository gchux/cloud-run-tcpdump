FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
ARG GCSFUSE_VERSION='2.1.0'
USER 0:0
RUN apt-get -y -qq update > /dev/null && apt-get install -qq -y tzdata curl fuse tcpdump > /dev/null && apt-get -qq clean > /dev/null
RUN curl -o /gcsfuse.deb -L \
    https://github.com/GoogleCloudPlatform/gcsfuse/releases/download/v${GCSFUSE_VERSION}/gcsfuse_${GCSFUSE_VERSION}_amd64.deb \
    && dpkg -i --force-all /gcsfuse.deb && rm -vf /gcsfuse.deb
COPY ./bin/supervisord /bin/supervisord
COPY ./bin/tcpdumpw /bin/tcpdumpw
COPY ./bin/pcap_fsn /bin/pcap_fsn
COPY ./scripts/create_pcap_dir /scripts/create_pcap_dir
COPY ./scripts/start_pcapfsn /scripts/start_pcapfsn
COPY ./scripts/start_tcpdump /scripts/start_tcpdump
COPY ./tcpdump.conf /tcpdump.conf
COPY ./scripts/init /init
ENTRYPOINT ["/init"]
