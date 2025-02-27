-- Migration: Add status and last_ping_timestamp columns to discv4.nodes
-- Version: 1

BEGIN;

ALTER TABLE discv4.nodes
ADD COLUMN is_online BOOLEAN DEFAULT NULL;

ALTER TABLE discv4.nodes
ADD COLUMN last_ping_timestamp TIMESTAMP;

COMMIT;


-- Rollback: Remove status and last_ping_timestamp columns
-- BEGIN;
--
-- ALTER TABLE discv4.nodes
-- DROP COLUMN status;
--
-- ALTER TABLE discv4.nodes
-- DROP COLUMN last_ping_timestamp;
--
-- COMMIT;
