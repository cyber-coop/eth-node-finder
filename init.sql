CREATE SCHEMA IF NOT EXISTS discv4;
CREATE TABLE IF NOT EXISTS discv4.nodes (
    address TEXT NOT NULL,
    tcp_port INT,
    udp_port INT,
    id BYTEA NOT NULL PRIMARY KEY,
    network_id BIGINT,
    client TEXT,
    capabilities JSON
);