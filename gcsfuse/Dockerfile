# syntax=docker/dockerfile:1.4
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM --platform=linux/amd64 golang:1.23.4-alpine AS builder

RUN apk add git patch

ARG GCSFUSE_VERSION="2.7.0"
ARG GCSFUSE_REPO="/run/gcsfuse"


COPY ./patch /patch
RUN git clone --depth 1 --branch v${GCSFUSE_VERSION} \
  https://github.com/GoogleCloudPlatform/gcsfuse.git ${GCSFUSE_REPO} \
  && patch ${GCSFUSE_REPO}/internal/fs/fs.go /patch/internal/fs/fs.go

WORKDIR ${GCSFUSE_REPO}/

RUN git diff internal/fs/fs.go

RUN go install ./tools/build_gcsfuse
RUN build_gcsfuse . /tmp $(git log -1 --format=format:"%H")

FROM scratch AS releaser

COPY --link --from=builder /tmp/bin/gcsfuse /
COPY --link --from=builder /tmp/sbin/mount.gcsfuse /
