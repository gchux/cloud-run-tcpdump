FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
ARG GCSFUSE_VERSION='2.1.0'
RUN apt-get -qq update && apt-get install -qq -y curl fuse tcpdump && apt-get -qq clean
RUN curl -o /gcsfuse.deb -L \
    https://github.com/GoogleCloudPlatform/gcsfuse/releases/download/v${GCSFUSE_VERSION}/gcsfuse_${GCSFUSE_VERSION}_amd64.deb \
    && dpkg -i --force-all /gcsfuse.deb && rm -vf /gcsfuse.deb
COPY ./bin/pcap_fsn /pcap_fsn
COPY ./tcpdump /tcpdump
USER 0:0
ENTRYPOINT ["/tcpdump"]
