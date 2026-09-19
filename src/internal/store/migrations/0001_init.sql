CREATE TABLE schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE events (
	event_id BYTEA PRIMARY KEY,
	seq BIGINT GENERATED ALWAYS AS IDENTITY,
	event_type INTEGER NOT NULL,
	account_id BYTEA NOT NULL,
	wire BYTEA NOT NULL,
	CONSTRAINT events_event_id_len CHECK (octet_length(event_id) = 16),
	CONSTRAINT events_account_id_len CHECK (octet_length(account_id) = 32),
	CONSTRAINT events_wire_not_empty CHECK (octet_length(wire) > 0)
);

CREATE INDEX events_seq_idx ON events (seq);
CREATE INDEX events_account_seq_idx ON events (account_id, seq);

CREATE TABLE peers (
	peer_instance_id BYTEA PRIMARY KEY,
	protocol_version TEXT NOT NULL DEFAULT '',
	capabilities TEXT[] NOT NULL DEFAULT '{}',
	cursor BYTEA,
	last_successful_sync TIMESTAMPTZ,
	CONSTRAINT peers_instance_id_len CHECK (octet_length(peer_instance_id) = 32)
);

CREATE TABLE peer_cursors (
	peer_instance_id BYTEA NOT NULL REFERENCES peers (peer_instance_id) ON DELETE CASCADE,
	interest_hash BYTEA NOT NULL,
	cursor_seq BIGINT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (peer_instance_id, interest_hash),
	CONSTRAINT peer_cursors_hash_len CHECK (octet_length(interest_hash) = 32)
);