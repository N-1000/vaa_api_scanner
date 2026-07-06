-- Initial schema for LokiTrace / VAA Brain Cognitive Memory

-- 1. Grammar memory to avoid redundant fuzzing
CREATE TABLE IF NOT EXISTS grammar_entries (
    path VARCHAR(512) NOT NULL,
    param_name VARCHAR(256) NOT NULL,
    param_data JSONB NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (path, param_name)
);

-- 2. Exploit memory with decay factor tracking
CREATE TABLE IF NOT EXISTS exploit_memory (
    domain VARCHAR(256) NOT NULL,
    norm_path VARCHAR(512) NOT NULL,
    vuln_type VARCHAR(64) NOT NULL,
    payload VARCHAR(512) NOT NULL,
    confidence NUMERIC(4,3) NOT NULL,
    scan_count INT DEFAULT 1,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (domain, norm_path, vuln_type, payload)
);

-- 3. Endpoint intelligence metadata store
CREATE TABLE IF NOT EXISTS endpoint_intel (
    domain VARCHAR(256) NOT NULL,
    norm_path VARCHAR(512) NOT NULL,
    method VARCHAR(16) NOT NULL,
    requires_auth BOOLEAN DEFAULT FALSE,
    auth_scheme VARCHAR(64),
    last_status INT,
    param_schema JSONB,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (domain, norm_path, method)
);

-- 4. Scan mission history
CREATE TABLE IF NOT EXISTS scan_history (
    domain VARCHAR(256) NOT NULL,
    scan_id UUID PRIMARY KEY,
    status VARCHAR(32) DEFAULT 'running',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP,
    total_findings INT DEFAULT 0
);

-- Optional indexes to speed up lookups during massive fuzzing
CREATE INDEX IF NOT EXISTS idx_exploit_memory_domain ON exploit_memory(domain);
CREATE INDEX IF NOT EXISTS idx_endpoint_intel_lookup ON endpoint_intel(domain, norm_path);
