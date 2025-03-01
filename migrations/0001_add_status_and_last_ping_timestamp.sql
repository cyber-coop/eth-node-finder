-- Migration: Add last_ping_timestamp columns to discv4.nodes
-- Version: 1

BEGIN;

ALTER TABLE discv4.nodes
ADD COLUMN last_ping_timestamp TIMESTAMP DEFAULT NULL;

COMMIT;


-- Rollback: Remove last_ping_timestamp columns
-- BEGIN;
--
-- ALTER TABLE discv4.nodes
-- DROP COLUMN last_ping_timestamp;
--
-- COMMIT;
