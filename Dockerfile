##### BUILDER #####
FROM rust:latest as builder

WORKDIR /usr/src/prototype
COPY . .
RUN cargo install --path .

##### RUNNER #####
FROM debian:bookworm

LABEL author="Lola Rigaut-Luczak <me@laflemme.lol>"
LABEL description="Program that queries the network for new peers using DISCV4."

COPY --from=builder /usr/local/cargo/bin/node-finder /usr/local/bin/node-finder

RUN apt-get update && rm -rf /var/lib/apt/lists/*
#RUN apt-get install -y libc6

# default env
ENV RUST_LOG "prototype=info"

CMD node-finder 