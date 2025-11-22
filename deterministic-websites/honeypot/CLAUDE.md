# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Double-Agent honeypot** for the def/acc hackathon in London. It serves two purposes:
1. A public-facing hackathon event website with information about the event
2. An AI agent detection honeypot that classifies visitors as Human, Scraper, or AI Agent

The honeypot uses behavioral analysis and a point-based scoring system to detect and classify autonomous AI agents probing the system. All attempts are logged to Supabase with MITRE ATT&CK technique mappings.

## Development Commands

```bash
# Start development server
pnpm dev

# Build for production
pnpm build

# Start production server
pnpm start

# Run linter
pnpm lint
```

The dev server runs at http://localhost:3000

## Project Architecture

### Technology Stack
- **Framework**: Next.js 16 (App Router)
- **Language**: TypeScript (strict mode)
- **Styling**: Tailwind CSS v4
- **Database**: Supabase (PostgreSQL)
- **Runtime**: React 19

### Directory Structure

```
app/
  api/
    [...slug]/route.ts     # Catch-all honeypot API route with detection
  components/              # React components (Navbar, AnimatedCounter, LoginButton)
  page.tsx                 # Main hackathon landing page
  layout.tsx               # Root layout with fonts and metadata
  globals.css              # Global styles and Tailwind imports

lib/
  detection.ts             # Core detection engine (scoring, classification, analysis)
  honeypot-config.ts       # Fake API key configuration (honeypot bait)
  honeypot-utils.ts        # Legacy API key validation (deprecated)
  supabase.ts              # Supabase client configuration
```

## Detection System Architecture

### Core Detection Flow

```
Incoming Request → Metadata Extraction → Session Grouping → Behavior Analysis → Classification
                         ↓                    ↓                   ↓                 ↓
                    IP, UA, Path,       10-min timeout       Score 0-100      human/scraper/ai_agent
                    Method, Body        IP + User-Agent      8+ indicators
```

### Agent-Likeness Scoring Algorithm

The detection engine (`lib/detection.ts`) uses a point-based heuristic system:

| Detection Factor | Points | What It Detects |
|-----------------|--------|-----------------|
| Documentation access first | +20 | Agents reading /docs, /openapi before probing |
| Systematic probing (>5 endpoints) | +25 | Methodical API exploration |
| Admin/internal endpoint access | +15 | Privilege escalation attempts |
| SQL injection patterns | +25 | Automated vulnerability scanning |
| Bot-like User-Agent | +15 | Known bot signatures |
| Multiple HTTP methods (>2) | +15 | Comprehensive API testing |
| Honey token usage | +30 | Credential harvesting and reuse |
| High endpoint diversity | +10 | Exploring many different endpoints |
| Regular request intervals | +25 | Automated timing patterns |

### Classification Thresholds

- **Score >= 70** → `ai_agent` (sophisticated automated probing)
- **Score 40-69** → `scraper` (simple automated tool)
- **Score < 40** → `human` (irregular browsing)

### Detection Signals

**SQL Injection Detection** - Regex patterns scanned in query params and body:
- `SELECT`, `DROP`, `INSERT`, `UPDATE`, `DELETE` statements
- Comment injection (`'--`, `/*`, `*/`)
- Tautologies (`1=1`, `' OR '`)
- `UNION SELECT`, time-based (`SLEEP`, `WAITFOR DELAY`)

**Bot User-Agent Detection** - Checks for:
- `bot`, `crawler`, `spider`, `scraper`
- `python`, `axios`, `curl`, `wget`
- `gpt`, `claude`, `openai`, `anthropic`, `langchain`
- `selenium`, `puppeteer`, `playwright`, `headless`

**Path Classification**:
- Docs paths: `/docs`, `/documentation`, `/api-docs`, `/swagger`
- OpenAPI paths: `/openapi`, `/openapi.json`, `/swagger.json`
- Admin paths: `/admin`, `/dashboard`, `/internal`, `/debug`
- Internal paths: `/shell`, `/exec`, `/eval`, `/.env`, `/config`

### Session Management

Sessions are grouped by **IP + User-Agent** with a **10-minute timeout**:
- Requests from the same IP+UA within 10 minutes belong to the same session
- Session state persists: endpoints visited, methods used, detection flags
- Allows building behavioral profile over multiple requests

### Honey Tokens

The system generates fake credentials that trigger alerts when used:
- API keys: `sk_live_*`, `sk_test_*`
- AWS keys: `AKIAIOSFODNN7EXAMPLE`
- GitHub tokens: `ghp_*`
- JWTs with fake admin payloads

When a honey token is detected in any request (headers, body, query), the session is flagged.

## Database Schema (v2)

Two main tables in `supabase-schema-v2.sql`:

### `sessions` table
Tracks visitor sessions with behavioral flags and classification:
- `id`, `ip`, `user_agent`, `start_time`, `last_activity`
- `request_count`, `endpoints_called`, `methods_used`
- Detection flags: `looked_at_docs`, `tried_openapi`, `tried_admin`, `systematic_probing`, `sql_injection_attempted`, `used_honey_token`
- `agent_likeness_score`, `classification`, `classification_reasons`

### `requests` table
Individual request logs with full metadata:
- `session_id`, `timestamp`, `ip`, `user_agent`
- `method`, `path`, `query_params`, `body`, `headers`
- `response_status`, `response_time_ms`
- `api_key_status`, `sql_injection_detected`, `bot_user_agent_detected`
- `technique_id` (MITRE mapping)

### `honey_tokens` table
Tracks fake credentials and their usage:
- `token_type`, `token_value`, `triggered`, `triggered_at`, `triggered_by_ip`

## MITRE ATT&CK Mapping

Detection results are mapped to MITRE techniques:
- **T1552** (Unsecured Credentials): Correct API key or honey token used
- **T1110** (Brute Force): Incorrect API key attempts
- **T1190** (Exploit Public-Facing Application): SQL injection or general probing

## Environment Variables

Required in `.env.local`:
```
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
```

**Note**: The Supabase client uses the service role key (not anon key) to bypass Row Level Security for server-side logging.

## API Route Handling

The catch-all route at `app/api/[...slug]/route.ts` handles ALL HTTP methods (GET, POST, PUT, PATCH, DELETE, OPTIONS). Each request:

1. Extracts full metadata (IP, UA, path, query, body, headers)
2. Checks for API keys in headers
3. Analyzes request with `analyzeRequest()` from `lib/detection.ts`
4. Logs session and request data to Supabase
5. Returns realistic responses to maintain honeypot believability

Console output shows real-time detection:
```
[Detection] Session: a1b2c3d4... | Score: 65 | Class: scraper | Reasons: docs_first, admin_probing
[Detection] SQL injection detected from 192.168.1.1
[Detection] HONEY TOKEN TRIGGERED from 10.0.0.5!
```

## Key Files

| File | Purpose |
|------|---------|
| `lib/detection.ts` | Core detection engine - scoring, classification, analysis |
| `lib/honeypot-config.ts` | Fake API key bait |
| `app/api/[...slug]/route.ts` | Catch-all API honeypot with detection integration |
| `supabase-schema-v2.sql` | Enhanced database schema for detection data |

## Important Notes

- The API key in `lib/honeypot-config.ts` is intentionally fake and exposed as bait
- All `/api/*` routes are honeypots - they don't perform real operations
- Detection is async and non-blocking - responses are fast
- Sessions persist across requests for behavioral profiling
- Honey tokens in `supabase-schema-v2.sql` are seeded with common fake credential patterns
