# How to build

## Using `go`

```sh
go generate ./... && go build -o pcap cmd/pcap.go
```

> **NOTE**: apply [`gofumpt`](https://github.com/mvdan/gofumpt) before commit; i/e: `gofumpt -l -w .`

## Using [Taskfile](https://taskfile.dev/)

### Quick build

```sh
task -v build
```

### Verbose build

```sh
task -v dist
```
