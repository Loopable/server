ALTER TABLE events ADD COLUMN group_id BYTEA;
CREATE INDEX events_group_seq_idx ON events (group_id, seq);

CREATE TABLE objects (
	object_id BYTEA NOT NULL,
	version_id BYTEA NOT NULL,
	seq BIGINT GENERATED ALWAYS AS IDENTITY,
	object_type INTEGER NOT NULL,
	encryption_suite INTEGER NOT NULL,
	blob_backed BOOLEAN NOT NULL DEFAULT false,
	ciphertext_length BIGINT NOT NULL DEFAULT 0,
	wire BYTEA NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (object_id, version_id),
	CONSTRAINT objects_object_id_len CHECK (octet_length(object_id) = 32),
	CONSTRAINT objects_version_id_len CHECK (octet_length(version_id) = 32),
	CONSTRAINT objects_wire_not_empty CHECK (octet_length(wire) > 0)
);

CREATE INDEX objects_id_seq_idx ON objects (object_id, seq);
CREATE INDEX objects_seq_idx ON objects (seq);