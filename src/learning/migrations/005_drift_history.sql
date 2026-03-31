-- ShieldX Migration 005: Drift History
-- Tracks model/pattern confidence drift over time

-- =============================================================================
-- shieldx_drift_reports: Detected drift events
-- =============================================================================
CREATE TABLE IF NOT EXISTS shieldx_drift_reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    drift_type      TEXT NOT NULL
                        CHECK (drift_type IN ('gradual', 'sudden', 'recurring')),
    affected_phases TEXT[] NOT NULL,
    confidence_drop FLOAT NOT NULL,
    suggested_action TEXT NOT NULL,
    sample_count    INTEGER NOT NULL,
    metadata        JSONB
);

CREATE INDEX IF NOT EXISTS idx_drift_detected_at ON shieldx_drift_reports (detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_drift_type ON shieldx_drift_reports (drift_type);
