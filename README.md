# Ethereum Node finder

Collect all the node found on Ethereum DISCV4 protocol (but not all them are Ethereum). The nodes IP are stored in a postgres database.

## Quick Start

```
$ git clone https://github.com/cyber-coop/eth-node-finder.git
$ mv config.example.toml config.yml
$ docker compose up
```

## Dev

Start postgres via docker compose.
```
$ docker compose up -d postgres
```

Create your `config.toml` from `config.example.toml`.

Start `discv` to see it runnning
```
$ RUST_LOG=info cargo r --bin discv
```

Start `ping` to see it runnning
```
$ RUST_LOG=info cargo r --bin ping
```

Start `status` to see it runnning
```
$ RUST_LOG=info cargo r --bin status
```

## Postgres

```
$ docker exec -ti postgres bash
```

Once inside the container
```
$ psql -U postgres -d blockchains
> SELECT * FROM discv4.nodes;
> SELECT * FROM discv4.nodes WHERE network_id IS NOT NULL;
```