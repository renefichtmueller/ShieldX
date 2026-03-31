-- ShieldX Migration 004: Conversation State Tracking
-- Multi-turn conversation analysis for escalation detection

-- =============================================================================
-- shieldx_conversation_state: Aggregate state per session
-- =============================================================================
CREATE TABLE IF NOT EXISTS shieldx_conversation_state (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id          TEXT NOT NULL REFERENCES shieldx_sessions(session_key) ON DELETE CASCADE,
    cumulative_intent   JSONB,
    suspicion_score     FLOAT NOT NULL DEFAULT 0.0,
    escalation_detected BOOLEAN NOT NULL DEFAULT FALSE,
    topic_drift         FLOAT NOT NULL DEFAULT 0.0,
    authority_shifts    INTEGER NOT NULL DEFAULT 0,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_conv_state_session ON shieldx_conversation_state (session_id);
CREATE INDEX IF NOT EXISTS idx_conv_state_escalation ON shieldx_conversation_state (escalation_detected)
    WHERE escalation_detected = TRUE;

-- =============================================================================
-- shieldx_conversation_turns: Individual turns within a session
-- =============================================================================
CREATE TABLE IF NOT EXISTS shieldx_conversation_turns (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      TEXT NOT NULL,
    turn_index      INTEGER NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    role            TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    trust_tag       TEXT NOT NULL,
    threat_signals  JSONB DEFAULT '[]',
    suspicion_delta FLOAT NOT NULL DEFAULT 0.0
);

CREATE INDEX IF NOT EXISTS idx_conv_turns_session ON shieldx_conversation_turns (session_id);
CREATE INDEX IF NOT EXISTS idx_conv_turns_session_index ON shieldx_conversation_turns (session_id, turn_index);
CREATE INDEX IF NOT EXISTS idx_conv_turns_timestamp ON shieldx_conversation_turns (timestamp DESC);
