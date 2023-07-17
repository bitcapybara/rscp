# rscp

a rust implementation of scp, using QUIC protocol

## Features
* Use QUIC protocol
* Entire file SHA256 checksum

## Usage

### server

```bash
cargo run --bin rscp -- --server
```

### client

```bash
cargo run --bin rscp -- --source localhost:src/path --target dst/path
cargo run --bin rscp -- --source src/path --target localhost:dst/path
```
