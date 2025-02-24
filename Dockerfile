##### BUILDER #####
FROM rust:latest as builder

WORKDIR /usr/src/prototype
COPY . .
RUN cargo install --path .

##### RUNNER #####
FROM debian:bookworm

LABEL author="Lola Rigaut-Luczak <me@laflemme.lol>"
LABEL description="Programs that map nodes network (Ethereum and Ethereum like)."

COPY --from=builder /usr/local/cargo/bin/discv /usr/local/bin/discv
COPY --from=builder /usr/local/cargo/bin/ping /usr/local/bin/ping
COPY --from=builder /usr/local/cargo/bin/server /usr/local/bin/server
COPY --from=builder /usr/local/cargo/bin/status /usr/local/bin/status


RUN apt-get update && rm -rf /var/lib/apt/lists/*
#RUN apt-get install -y libc6

# default env
ENV RUST_LOG "info"

CMD discv