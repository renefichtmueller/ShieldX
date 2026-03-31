-- ShieldX Migration 002: Embeddings (pgvector)
-- Vector storage for semantic similarity detection

CREATE EXTENSION IF NOT EXISTS vector;

-- =============================================================================
-- shieldx_embeddings: Vector embeddings for prompt inputs
-- =============================================================================
CREATE TABLE IF NOT EXISTS shieldx_embeddings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    input_hash      TEXT NOT NULL UNIQUE,
    embedding       vector(768),
    kill_chain_phase TEXT NOT NULL,
    threat_level    TEXT NOT NULL,
    source          TEXT NOT NULL DEFAULT 'learned',
    metadata        JSONB
);

-- IVFFlat index for cosine similarity search (nomic-embed-text 768d)
CREATE INDEX IF NOT EXISTS idx_embeddings_cosine
    ON shieldx_embeddings
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);
