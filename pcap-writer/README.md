# How to build

```sh
go generate ./... && go build -o pcap cmd/pcap.go
```

> **NOTE**: apply [`gofumpt`](https://github.com/mvdan/gofumpt) before commit; i/e: `gofumpt -l -w .`
