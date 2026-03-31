-- ShieldX Migration 003: Attack Graph
-- Tracks attack technique evolution and relationships

-- =============================================================================
-- shieldx_attack_nodes: Individual attack techniques
-- =============================================================================
CREATE TABLE IF NOT EXISTS shieldx_attack_nodes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    technique       TEXT NOT NULL,
    kill_chain_phase TEXT NOT NULL,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    frequency       INTEGER NOT NULL DEFAULT 1,
    success_rate    FLOAT NOT NULL DEFAULT 0.0,
    variants        JSONB DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_attack_nodes_technique ON shieldx_attack_nodes (technique);
CREATE INDEX IF NOT EXISTS idx_attack_nodes_kill_chain ON shieldx_attack_nodes (kill_chain_phase);
CREATE INDEX IF NOT EXISTS idx_attack_nodes_last_seen ON shieldx_attack_nodes (last_seen DESC);

-- =============================================================================
-- shieldx_attack_edges: Relationships between attack techniques
-- =============================================================================
CREATE TABLE IF NOT EXISTS shieldx_attack_edges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id       UUID NOT NULL REFERENCES shieldx_attack_nodes(id) ON DELETE CASCADE,
    target_id       UUID NOT NULL REFERENCES shieldx_attack_nodes(id) ON DELETE CASCADE,
    relationship    TEXT NOT NULL
                        CHECK (relationship IN ('evolved_from', 'combined_with', 'variant_of', 'precedes')),
    weight          FLOAT NOT NULL DEFAULT 1.0,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attack_edges_source ON shieldx_attack_edges (source_id);
CREATE INDEX IF NOT EXISTS idx_attack_edges_target ON shieldx_attack_edges (target_id);
CREATE INDEX IF NOT EXISTS idx_attack_edges_relationship ON shieldx_attack_edges (relationship);
