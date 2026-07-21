CREATE TABLE IF NOT EXISTS events (
    event_digest TEXT PRIMARY KEY,
    event_json TEXT NOT NULL,
    human_code TEXT UNIQUE,
    expires_at TEXT,
    state TEXT NOT NULL CHECK (state IN ('pending', 'decided')),
    delivery_state TEXT NOT NULL CHECK (delivery_state IN ('pending', 'claimed', 'accepted', 'delivered', 'failed')),
    delivery_claimed_at TEXT,
    telnyx_message_id TEXT,
    telnyx_final_status TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_digest TEXT NOT NULL UNIQUE,
    event_digest TEXT NOT NULL UNIQUE,
    signed_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (event_digest) REFERENCES events(event_digest)
);

CREATE TABLE IF NOT EXISTS webhook_events (
    webhook_id TEXT PRIMARY KEY,
    processed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sms_monthly (
    month TEXT PRIMARY KEY,
    attempted_count INTEGER NOT NULL CHECK (attempted_count >= 0 AND attempted_count <= 200)
);

-- Exactly one private Telegram chat may be paired.  The ID is never returned
-- by the relay and is kept outside source control with the D1 database.
CREATE TABLE IF NOT EXISTS telegram_recipient (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    chat_id TEXT NOT NULL UNIQUE,
    paired_at TEXT NOT NULL
);
