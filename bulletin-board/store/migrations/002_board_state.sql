CREATE TABLE IF NOT EXISTS board_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO board_state (key, value) VALUES ('sealed', 'false') ON CONFLICT DO NOTHING;
