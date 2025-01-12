# Itegration Test

This directory contains the assets to create a container image for a Cloud Run ready SSH server with:

- `libpcap`: https://github.com/the-tcpdump-group/libpcap
- `tcpdump`: https://github.com/the-tcpdump-group/tcpdump
- `gopacket`: https://github.com/google/gopacket

This SSH server allows to test Cloud Run compatibility with different versions of the aforementioned dependencies.

## How to Build:

```sh
docker build -t ${IMAGE_URI} .
```

## Available Build Arguments

- `LIBPCAP_VERSION`
  - `LIBPCAP_DL_FNAME`: `libpcap` bundle filename at https://www.tcpdump.org/release/
- `TCPDUMP_VERSION`
  - `TCPDUMP_DL_FNAME`: `tcpdump` bundle filename at https://www.tcpdump.org/release/
- `SSH_USER`: SSH username (must be `root`).
- `SSH_PASS`: password for SSH login.
- `WEB_PORT`: TCP port where the SSH web server accepts connections.
