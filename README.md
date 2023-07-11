# rscp

a rust implementation of scp, using QUIC protocol

* [x] QUIC bidirectional stream
* [x] SHA256 checksum
* [x] One coroutine per file
* [ ] DER CA format support
* [ ] Dry run mode
* [ ] File compress, File content chrunk

## CMD

### server

```bash
cargo run --bin rscp -- -s
```

### client

```bash
cargo run --bin rscp localhost:src/path dst/path
cargo run --bin rscp src/path localhost:dst/path
```
