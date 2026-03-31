-- ShieldX Migration 001: Initial Schema
-- Creates core tables: patterns, incidents, feedback, sessions

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- shieldx_patterns: Detection patterns (regex, embedding, yara, rule)
-- =============================================================================
CREATE TABLE IF NOT EXISTS shieldx_patterns (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    pattern_text    TEXT NOT NULL,
    pattern_type    TEXT NOT NULL CHECK (pattern_type IN ('regex', 'embedding', 'yara', 'rule')),
    kill_chain_phase TEXT NOT NULL,
    confidence_base FLOAT NOT NULL DEFAULT 0.5,
    hit_count       INTEGER NOT NULL DEFAULT 0,
    false_positive_count INTEGER NOT NULL DEFAULT 0,
    source          TEXT NOT NULL DEFAULT 'builtin'
                        CHECK (source IN ('builtin', 'learned', 'community', 'red_team')),
    enabled         BOOLEAN NOT NULL DEFAULT true,
    metadata        JSONB,
    UNIQUE (pattern_text, pattern_type)
);

CREATE INDEX IF NOT EXISTS idx_patterns_kill_chain_phase ON shieldx_patterns (kill_chain_phase);
CREATE INDEX IF NOT EXISTS idx_patterns_enabled ON shieldx_patterns (enabled);
CREATE INDEX IF NOT EXISTS idx_patterns_source ON shieldx_patterns (source);

-- =============================================================================
-- shieldx_incidents: Logged security incidents
-- =============================================================================
CREATE TABLE IF NOT EXISTS shieldx_incidents (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    session_id        TEXT,
    user_id           TEXT,
    threat_level      TEXT NOT NULL,
    kill_chain_phase  TEXT NOT NULL,
    action_taken      TEXT NOT NULL,
    matched_rule_ids  TEXT[],
    input_hash        TEXT NOT NULL,
    mitigation_applied TEXT,
    false_positive    BOOLEAN DEFAULT FALSE,
    atlas_mapping     TEXT,
    owasp_mapping     TEXT,
    notes             TEXT,
    metadata          JSONB
);

CREATE INDEX IF NOT EXISTS idx_incidents_occurred_at ON shieldx_incidents (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_threat_level ON shieldx_incidents (threat_level);
CREATE INDEX IF NOT EXISTS idx_incidents_kill_chain_phase ON shieldx_incidents (kill_chain_phase);
CREATE INDEX IF NOT EXISTS idx_incidents_input_hash ON shieldx_incidents (input_hash);

-- =============================================================================
-- shieldx_feedback: User/operator feedback on scan results
-- =============================================================================
CREATE TABLE IF NOT EXISTS shieldx_feedback (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submitted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scan_id           UUID NOT NULL,
    incident_id       UUID REFERENCES shieldx_incidents(id),
    is_false_positive BOOLEAN NOT NULL,
    notes             TEXT,
    pattern_adjustment JSONB
);

-- =============================================================================
-- shieldx_sessions: Tracked conversation/task sessions
-- =============================================================================
CREATE TABLE IF NOT EXISTS shieldx_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    session_key     TEXT UNIQUE NOT NULL,
    task_description TEXT,
    allowed_tools   TEXT[],
    message_count   INTEGER NOT NULL DEFAULT 0,
    suspicion_score FLOAT NOT NULL DEFAULT 0.0,
    trust_score     FLOAT NOT NULL DEFAULT 1.0,
    checkpoints     JSONB DEFAULT '[]',
    active          BOOLEAN NOT NULL DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_sessions_session_key ON shieldx_sessions (session_key);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON shieldx_sessions (active);
