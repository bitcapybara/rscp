# rscp

a rust implementation of scp, using QUIC protocol

## Features
* [x] Use QUIC protocol
* [x] Entire file SHA256 checksum
* [x] One coroutine per file
* [ ] Dry run mode
* [ ] File compress, File content chrunk

## CMD

### server

```bash
cargo run --bin rscp -- -s
```

### client

```bash
cargo run --bin rscp -- --source localhost:src/path --target dst/path
cargo run --bin rscp -- --source src/path --target localhost:dst/path
```
