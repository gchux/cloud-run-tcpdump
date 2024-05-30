FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
ARG GCSFUSE_VERSION='2.1.0'
USER 0:0
RUN apt-get -y -qq update > /dev/null && apt-get install -qq -y tzdata curl fuse tcpdump > /dev/null && apt-get -qq clean > /dev/null
RUN curl -o /gcsfuse.deb -L \
    https://github.com/GoogleCloudPlatform/gcsfuse/releases/download/v${GCSFUSE_VERSION}/gcsfuse_${GCSFUSE_VERSION}_amd64.deb \
    && dpkg -i --force-all /gcsfuse.deb && rm -vf /gcsfuse.deb
COPY ./bin /bin
COPY ./scripts /scripts
COPY ./tcpdump.conf /tcpdump.conf
COPY ./scripts/init /init
ENTRYPOINT ["/init"]
