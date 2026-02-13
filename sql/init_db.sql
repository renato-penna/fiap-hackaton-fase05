-- ==========================================================
-- Schema: Cloud Architecture Security Analyzer
-- ==========================================================

-- Tabela principal de análises (usada por src/database.py)
CREATE TABLE IF NOT EXISTS analysis_history (
    id                  SERIAL PRIMARY KEY,
    image_name          VARCHAR(255) NOT NULL,
    total_components    INT          NOT NULL DEFAULT 0,
    risk_score          NUMERIC(5,1) NOT NULL DEFAULT 0.0,
    risk_level          VARCHAR(20)  NOT NULL DEFAULT 'LOW',
    components          JSONB,
    created_at          TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analysis_history_created_at
    ON analysis_history (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_analysis_history_risk_level
    ON analysis_history (risk_level);

-- Tabela legada de relatórios (mantida para compatibilidade)
CREATE TABLE IF NOT EXISTS reports (
    id                  SERIAL PRIMARY KEY,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    filename            VARCHAR(255) NOT NULL,
    risk_level          VARCHAR(20)  NOT NULL,
    risk_score          FLOAT        NOT NULL,
    total_components    INT          NOT NULL,
    total_risks         INT          NOT NULL,
    security_controls   JSONB        DEFAULT '[]',
    detections          JSONB        DEFAULT '[]',
    stride_analyses     JSONB        DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_reports_created_at  ON reports (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_risk_level  ON reports (risk_level);
