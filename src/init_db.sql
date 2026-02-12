-- ==========================================================
-- Schema: Relatórios STRIDE - Cloud Architecture Analyzer
-- ==========================================================

CREATE TABLE IF NOT EXISTS reports (
    id                  SERIAL PRIMARY KEY,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    filename            VARCHAR(255) NOT NULL,
    risk_level          VARCHAR(20)  NOT NULL,       -- LOW, MEDIUM, HIGH, CRITICAL
    risk_score          FLOAT        NOT NULL,       -- 0.0 a 1.0
    total_components    INT          NOT NULL,
    total_risks         INT          NOT NULL,
    security_controls   JSONB        DEFAULT '[]',   -- ["WAF", "Firewall"]
    detections          JSONB        DEFAULT '[]',   -- [{class, confidence, box}]
    stride_analyses     JSONB        DEFAULT '[]'    -- relatório STRIDE completo
);

-- Índices para consultas frequentes
CREATE INDEX IF NOT EXISTS idx_reports_created_at  ON reports (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_risk_level  ON reports (risk_level);
CREATE INDEX IF NOT EXISTS idx_reports_risk_score  ON reports (risk_score);
