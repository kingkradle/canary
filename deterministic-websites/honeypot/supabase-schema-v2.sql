-- Double-Agent Detection Schema v2
-- Enhanced honeypot detection with session tracking and agent-likeness scoring

-- Drop existing tables if they exist
DROP TABLE IF EXISTS requests CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS honey_tokens CASCADE;
DROP TABLE IF EXISTS vulnerability_logs CASCADE;
DROP TABLE IF EXISTS vulnerability_types CASCADE;

-- ============================================================================
-- SESSIONS TABLE
-- Groups requests by IP + User-Agent with 10-minute timeout
-- ============================================================================
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    start_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_time TIMESTAMPTZ,
    last_activity TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    request_count INT DEFAULT 0,
    endpoints_called JSONB DEFAULT '[]'::jsonb,

    -- Timing analysis
    avg_request_interval_ms FLOAT,
    interval_variance FLOAT,

    -- Detection flags
    looked_at_docs BOOLEAN DEFAULT FALSE,
    tried_openapi BOOLEAN DEFAULT FALSE,
    tried_admin BOOLEAN DEFAULT FALSE,
    tried_internal BOOLEAN DEFAULT FALSE,
    systematic_probing BOOLEAN DEFAULT FALSE,
    sql_injection_attempted BOOLEAN DEFAULT FALSE,
    used_honey_token BOOLEAN DEFAULT FALSE,

    -- HTTP methods used
    methods_used JSONB DEFAULT '[]'::jsonb,

    -- Scoring & Classification
    agent_likeness_score INT DEFAULT 0,
    classification TEXT DEFAULT 'unknown',  -- 'human', 'scraper', 'ai_agent'
    classification_reasons JSONB DEFAULT '[]'::jsonb,

    -- Unique constraint for session lookup
    CONSTRAINT unique_session UNIQUE (ip, user_agent)
);

-- ============================================================================
-- REQUESTS TABLE
-- Individual request logs with full metadata
-- ============================================================================
CREATE TABLE requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Request metadata
    ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    query_params JSONB,
    body JSONB,
    headers JSONB,

    -- Response info
    response_status INT,
    response_time_ms INT,

    -- Detection flags for this request
    api_key_status TEXT,  -- 'correct', 'wrong', 'none'
    api_key_used TEXT,
    sql_injection_detected BOOLEAN DEFAULT FALSE,
    bot_user_agent_detected BOOLEAN DEFAULT FALSE,

    -- MITRE mapping
    technique_id TEXT,
    vulnerability_type TEXT
);

-- ============================================================================
-- HONEY TOKENS TABLE
-- Fake credentials that trigger alerts when used
-- ============================================================================
CREATE TABLE honey_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_type TEXT NOT NULL,  -- 'api_key', 'jwt', 'aws_key', 'github_token'
    token_value TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    triggered BOOLEAN DEFAULT FALSE,
    triggered_at TIMESTAMPTZ,
    triggered_by_ip TEXT,
    triggered_by_session UUID REFERENCES sessions(id)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Sessions indexes
CREATE INDEX idx_sessions_ip ON sessions(ip);
CREATE INDEX idx_sessions_last_activity ON sessions(last_activity DESC);
CREATE INDEX idx_sessions_classification ON sessions(classification);
CREATE INDEX idx_sessions_agent_score ON sessions(agent_likeness_score DESC);
CREATE INDEX idx_sessions_start_time ON sessions(start_time DESC);

-- Requests indexes
CREATE INDEX idx_requests_session_id ON requests(session_id);
CREATE INDEX idx_requests_timestamp ON requests(timestamp DESC);
CREATE INDEX idx_requests_path ON requests(path);
CREATE INDEX idx_requests_ip ON requests(ip);
CREATE INDEX idx_requests_method ON requests(method);
CREATE INDEX idx_requests_technique_id ON requests(technique_id);

-- Honey tokens indexes
CREATE INDEX idx_honey_tokens_value ON honey_tokens(token_value);
CREATE INDEX idx_honey_tokens_triggered ON honey_tokens(triggered);

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================

-- Sessions RLS
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow read access to sessions"
    ON sessions FOR SELECT
    TO authenticated
    USING (true);

CREATE POLICY "Service role can manage sessions"
    ON sessions FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- Requests RLS
ALTER TABLE requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow read access to requests"
    ON requests FOR SELECT
    TO authenticated
    USING (true);

CREATE POLICY "Service role can manage requests"
    ON requests FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- Honey tokens RLS
ALTER TABLE honey_tokens ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow read access to honey tokens"
    ON honey_tokens FOR SELECT
    TO authenticated
    USING (true);

CREATE POLICY "Service role can manage honey tokens"
    ON honey_tokens FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- ============================================================================
-- SEED HONEY TOKENS
-- ============================================================================
INSERT INTO honey_tokens (token_type, token_value) VALUES
    ('api_key', 'sk_live_a1b2c3d4e5f6g7h8i9j0'),
    ('api_key', 'sk_test_secret_key_12345'),
    ('api_key', 'sk_afsldkfjslkjdfghsoiearhgf'),  -- Original honeypot key
    ('aws_key', 'AKIAIOSFODNN7EXAMPLE'),
    ('github_token', 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'),
    ('jwt', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');

-- ============================================================================
-- HELPER VIEWS
-- ============================================================================

-- View for recent AI agent sessions
CREATE OR REPLACE VIEW ai_agent_sessions AS
SELECT
    id,
    ip,
    user_agent,
    start_time,
    request_count,
    agent_likeness_score,
    classification,
    classification_reasons,
    looked_at_docs,
    tried_openapi,
    tried_admin,
    systematic_probing,
    sql_injection_attempted
FROM sessions
WHERE classification = 'ai_agent'
ORDER BY start_time DESC;

-- View for session summary stats
CREATE OR REPLACE VIEW session_stats AS
SELECT
    classification,
    COUNT(*) as session_count,
    AVG(agent_likeness_score) as avg_score,
    AVG(request_count) as avg_requests,
    SUM(CASE WHEN sql_injection_attempted THEN 1 ELSE 0 END) as sql_injection_attempts,
    SUM(CASE WHEN used_honey_token THEN 1 ELSE 0 END) as honey_token_uses
FROM sessions
GROUP BY classification;
