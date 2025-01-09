# GCSFuse patched

This directory contains the source code to clone, build and patch specific versions of [GCSFuse](https://github.com/GoogleCloudPlatform/gcsfuse).

Patching GCSFuse is required to make it compatible with **Cloud Run gen1**; see [GCSFuse issue #2753](https://github.com/GoogleCloudPlatform/gcsfuse/issues/2753).

> TL;DR: in **Cloud Run gen1**, an extra –and invalid– [`FlushFile`](https://github.com/GoogleCloudPlatform/gcsfuse/blob/v2.7.0/internal/fs/fs.go#L2542)
> operation will be issued after listing directories which will cause **GCSFuse** to panic and crash.

This patch file(s) prevent GCSFuse from `panic`ing and crashing at Cloud Run gen1 runtime.

## Directory Structure

- `.env`: environment variables files that contain the version of dependencies.
- `patch/`: directory that contains the patches to be applied broken down by **GCSFuse** version.
- `Dockerfile`: a modified version of the [**GCSFuse** original `Dockerfile`](https://github.com/GoogleCloudPlatform/gcsfuse/blob/master/Dockerfile).

## How to Build

1. Build GCSFuse patched:

   ```sh
   task -vf docker-build
   ```

2. GCSFuse binary files will be generated at `bin/` directory.

## Patched Files by GCSFuse version

### v2.7.0

- [interlan/fs/fs.go](https://github.com/GoogleCloudPlatform/gcsfuse/blob/v2.7.0/internal/fs/fs.go)
