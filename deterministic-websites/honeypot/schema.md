# Double-Agent Detection Database Schema (v2)

## Purpose
Tracks AI agent detection data including sessions, individual requests, behavioral analysis scores, and honey token triggers.

## Tables

### `sessions` (main tracking table)
Groups requests by IP + User-Agent with behavioral profiling.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | Yes (auto) | Primary key |
| `ip` | TEXT | Yes | Client IP address |
| `user_agent` | TEXT | Yes | Client User-Agent string |
| `start_time` | TIMESTAMPTZ | Yes (auto) | Session start time |
| `end_time` | TIMESTAMPTZ | No | Session end time |
| `last_activity` | TIMESTAMPTZ | Yes (auto) | Last request timestamp |
| `request_count` | INT | Yes | Number of requests in session |
| `endpoints_called` | JSONB | Yes | Array of unique endpoints accessed |
| `avg_request_interval_ms` | FLOAT | No | Average time between requests |
| `interval_variance` | FLOAT | No | Coefficient of variation for timing |
| `looked_at_docs` | BOOLEAN | Yes | Hit /docs or /documentation |
| `tried_openapi` | BOOLEAN | Yes | Hit /openapi or /swagger.json |
| `tried_admin` | BOOLEAN | Yes | Hit /admin or /dashboard |
| `tried_internal` | BOOLEAN | Yes | Hit /internal, /debug, /.env |
| `systematic_probing` | BOOLEAN | Yes | Accessed >5 unique endpoints |
| `sql_injection_attempted` | BOOLEAN | Yes | SQL patterns detected |
| `used_honey_token` | BOOLEAN | Yes | Used a fake credential |
| `methods_used` | JSONB | Yes | Array of HTTP methods used |
| `agent_likeness_score` | INT | Yes | Score 0-100 |
| `classification` | TEXT | Yes | 'unknown', 'human', 'scraper', 'ai_agent' |
| `classification_reasons` | JSONB | Yes | Array of scoring reasons |

**Constraint:** `UNIQUE (ip, user_agent)` - one session per IP+UA combo

**Indexes:** `ip`, `last_activity DESC`, `classification`, `agent_likeness_score DESC`, `start_time DESC`

### `requests` (individual request logs)
Full metadata for each HTTP request.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | Yes (auto) | Primary key |
| `session_id` | UUID | Yes (FK) | References sessions(id) |
| `timestamp` | TIMESTAMPTZ | Yes (auto) | Request timestamp |
| `ip` | TEXT | Yes | Client IP |
| `user_agent` | TEXT | Yes | Client User-Agent |
| `method` | TEXT | Yes | HTTP method (GET, POST, etc.) |
| `path` | TEXT | Yes | Request path |
| `query_params` | JSONB | No | URL query parameters |
| `body` | JSONB | No | Request body |
| `headers` | JSONB | No | Request headers (sanitized) |
| `response_status` | INT | No | HTTP response code |
| `response_time_ms` | INT | No | Server response time |
| `api_key_status` | TEXT | No | 'correct', 'wrong', 'none' |
| `api_key_used` | TEXT | No | The API key value if provided |
| `sql_injection_detected` | BOOLEAN | Yes | SQL pattern match |
| `bot_user_agent_detected` | BOOLEAN | Yes | Bot signature in UA |
| `technique_id` | TEXT | No | MITRE ATT&CK technique |
| `vulnerability_type` | TEXT | No | Classification label |

**Indexes:** `session_id`, `timestamp DESC`, `path`, `ip`, `method`, `technique_id`

### `honey_tokens` (fake credentials)
Tracks bait credentials and their usage.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | Yes (auto) | Primary key |
| `token_type` | TEXT | Yes | 'api_key', 'jwt', 'aws_key', 'github_token' |
| `token_value` | TEXT | Yes | The fake credential value |
| `created_at` | TIMESTAMPTZ | Yes (auto) | When token was created |
| `triggered` | BOOLEAN | Yes | Whether token was used |
| `triggered_at` | TIMESTAMPTZ | No | When token was first used |
| `triggered_by_ip` | TEXT | No | IP that used the token |
| `triggered_by_session` | UUID | No (FK) | Session that used the token |

**Constraint:** `UNIQUE (token_value)`

**Indexes:** `token_value`, `triggered`

## Views

### `ai_agent_sessions`
Quick view of all sessions classified as AI agents.

### `session_stats`
Aggregate statistics grouped by classification.

## Classification Thresholds

| Score Range | Classification | Description |
|-------------|----------------|-------------|
| >= 70 | `ai_agent` | Sophisticated automated probing |
| 40-69 | `scraper` | Simple automated tool |
| < 40 | `human` | Irregular browsing patterns |

## Scoring Factors

| Factor | Points | Trigger |
|--------|--------|---------|
| Documentation first | +20 | /docs or /openapi in first 3 requests |
| Systematic probing | +25 | >5 unique endpoints |
| Admin probing | +15 | /admin, /debug, /internal access |
| SQL injection | +25 | SQL patterns in params/body |
| Bot User-Agent | +15 | Known bot signatures |
| Multiple methods | +15 | >2 HTTP methods used |
| Honey token | +30 | Used a fake credential |
| High diversity | +10 | >70% unique endpoints |
| Regular intervals | +25 | Low timing variance (<0.3 CV) |

## Row Level Security

- Authenticated users: read access to all tables
- Service role: full access to all tables

## Usage Examples

```sql
-- Get all AI agent sessions
SELECT * FROM ai_agent_sessions;

-- Get classification breakdown
SELECT * FROM session_stats;

-- Find sessions that used honey tokens
SELECT * FROM sessions WHERE used_honey_token = true;

-- Get requests with SQL injection attempts
SELECT * FROM requests WHERE sql_injection_detected = true;

-- Find triggered honey tokens
SELECT * FROM honey_tokens WHERE triggered = true;
```

## Migration from v1

The v2 schema replaces `vulnerability_logs` and `vulnerability_types` with the new `sessions`, `requests`, and `honey_tokens` tables. Run `supabase-schema-v2.sql` to create the new schema.
