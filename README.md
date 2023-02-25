# rscp

a rust implementation of scp

* [ ] QUIC bidirectional stream
* [ ] SHA256 checksum
* [ ] One coroutine per file
* [ ] DER CA format support
* [ ] Dry run mode

## TLS
* 企业内部生成私有CA，签发给每台主机
* 服务端/客户端启动时，使用本机证书

## CMD

### server

```bash
ft -s --port=3322 --ca-path=./ca
```

### client

```bash
ft --port=3322 --ca-path=./ca 192.168.235.10:src/path dst/path
ft --port=3322 --ca-path=./ca src/path 192.168.235.10:dst/path
```
