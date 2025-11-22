/**
 * Double-Agent Detection System
 * AI Agent honeypot detection with session tracking and behavioral analysis
 */

import { supabase } from './supabase';

// ============================================================================
// TYPES
// ============================================================================

export interface Session {
  id: string;
  ip: string;
  user_agent: string;
  start_time: string;
  last_activity: string;
  request_count: number;
  endpoints_called: string[];
  avg_request_interval_ms: number | null;
  interval_variance: number | null;
  looked_at_docs: boolean;
  tried_openapi: boolean;
  tried_admin: boolean;
  tried_internal: boolean;
  systematic_probing: boolean;
  sql_injection_attempted: boolean;
  used_honey_token: boolean;
  methods_used: string[];
  agent_likeness_score: number;
  classification: 'unknown' | 'human' | 'scraper' | 'ai_agent';
  classification_reasons: string[];
}

export interface RequestMetadata {
  ip: string;
  userAgent: string;
  method: string;
  path: string;
  queryParams: Record<string, string>;
  body: unknown;
  headers: Record<string, string>;
  apiKeyStatus: 'correct' | 'wrong' | 'none';
  apiKeyUsed?: string;
  responseStatus: number;
  responseTimeMs: number;
}

export interface DetectionResult {
  sessionId: string;
  score: number;
  classification: 'human' | 'scraper' | 'ai_agent';
  reasons: string[];
  sqlInjectionDetected: boolean;
  botUserAgentDetected: boolean;
  honeyTokenTriggered: boolean;
  techniqueId: string;
}

// ============================================================================
// CONSTANTS
// ============================================================================

const SESSION_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes

// SQL injection patterns
const SQL_PATTERNS = [
  /SELECT\s+/i,
  /DROP\s+/i,
  /INSERT\s+/i,
  /UPDATE\s+.*SET/i,
  /DELETE\s+FROM/i,
  /'--/,
  /'\s*OR\s*/i,
  /1\s*=\s*1/,
  /\/\*/,
  /\*\//,
  /UNION\s+SELECT/i,
  /;\s*DROP/i,
  /;\s*DELETE/i,
  /EXEC(\s|\()/i,
  /xp_cmdshell/i,
  /WAITFOR\s+DELAY/i,
  /BENCHMARK\s*\(/i,
  /SLEEP\s*\(/i,
];

// Bot indicators in User-Agent
const BOT_INDICATORS = [
  'bot', 'crawler', 'spider', 'scraper',
  'python', 'axios', 'curl', 'wget', 'fetch',
  'postman', 'insomnia', 'httpie',
  'gpt', 'claude', 'openai', 'anthropic',
  'langchain', 'autogpt', 'agentgpt',
  'selenium', 'puppeteer', 'playwright',
  'headless', 'phantom',
];

// Documentation/API spec paths
const DOCS_PATHS = ['/docs', '/documentation', '/api-docs', '/swagger'];
const OPENAPI_PATHS = ['/openapi', '/openapi.json', '/openapi.yaml', '/swagger.json', '/api/schema'];
const ADMIN_PATHS = ['/admin', '/api/admin', '/dashboard', '/internal', '/debug', '/config'];
const INTERNAL_PATHS = ['/internal', '/debug', '/shell', '/exec', '/eval', '/.env', '/config'];

// ============================================================================
// SQL INJECTION DETECTION
// ============================================================================

export function detectSqlInjection(queryParams: Record<string, string>, body: unknown): boolean {
  const combined = JSON.stringify({ ...queryParams, ...(body || {}) });
  return SQL_PATTERNS.some(pattern => pattern.test(combined));
}

// ============================================================================
// BOT USER-AGENT DETECTION
// ============================================================================

export function detectBotUserAgent(userAgent: string): boolean {
  const lowerUA = userAgent.toLowerCase();
  return BOT_INDICATORS.some(indicator => lowerUA.includes(indicator));
}

// ============================================================================
// PATH CLASSIFICATION
// ============================================================================

export function isDocsPath(path: string): boolean {
  const lowerPath = path.toLowerCase();
  return DOCS_PATHS.some(p => lowerPath.includes(p));
}

export function isOpenApiPath(path: string): boolean {
  const lowerPath = path.toLowerCase();
  return OPENAPI_PATHS.some(p => lowerPath.includes(p));
}

export function isAdminPath(path: string): boolean {
  const lowerPath = path.toLowerCase();
  return ADMIN_PATHS.some(p => lowerPath.includes(p));
}

export function isInternalPath(path: string): boolean {
  const lowerPath = path.toLowerCase();
  return INTERNAL_PATHS.some(p => lowerPath.includes(p));
}

// ============================================================================
// HONEY TOKEN DETECTION
// ============================================================================

export async function checkHoneyToken(request: RequestMetadata): Promise<{ triggered: boolean; tokenType?: string }> {
  // Get all honey tokens
  const { data: tokens } = await supabase
    .from('honey_tokens')
    .select('token_value, token_type');

  if (!tokens) return { triggered: false };

  // Build haystack from all request data
  const haystack = JSON.stringify({
    headers: request.headers,
    body: request.body,
    query: request.queryParams,
    path: request.path,
  });

  for (const token of tokens) {
    if (haystack.includes(token.token_value)) {
      // Mark token as triggered
      await supabase
        .from('honey_tokens')
        .update({
          triggered: true,
          triggered_at: new Date().toISOString(),
          triggered_by_ip: request.ip,
        })
        .eq('token_value', token.token_value);

      return { triggered: true, tokenType: token.token_type };
    }
  }

  return { triggered: false };
}

// ============================================================================
// SESSION MANAGEMENT
// ============================================================================

export async function getOrCreateSession(ip: string, userAgent: string): Promise<Session> {
  const now = new Date();
  const timeoutThreshold = new Date(now.getTime() - SESSION_TIMEOUT_MS);

  // Try to find existing active session
  const { data: existingSession } = await supabase
    .from('sessions')
    .select('*')
    .eq('ip', ip)
    .eq('user_agent', userAgent)
    .gte('last_activity', timeoutThreshold.toISOString())
    .single();

  if (existingSession) {
    return existingSession as Session;
  }

  // Create new session (upsert to handle race conditions)
  const { data: newSession, error } = await supabase
    .from('sessions')
    .upsert({
      ip,
      user_agent: userAgent,
      start_time: now.toISOString(),
      last_activity: now.toISOString(),
      request_count: 0,
      endpoints_called: [],
      methods_used: [],
      agent_likeness_score: 0,
      classification: 'unknown',
      classification_reasons: [],
    }, {
      onConflict: 'ip,user_agent',
    })
    .select()
    .single();

  if (error) {
    console.error('[Detection] Failed to create session:', error);
    // Return a default session object
    return {
      id: 'temp-' + Date.now(),
      ip,
      user_agent: userAgent,
      start_time: now.toISOString(),
      last_activity: now.toISOString(),
      request_count: 0,
      endpoints_called: [],
      avg_request_interval_ms: null,
      interval_variance: null,
      looked_at_docs: false,
      tried_openapi: false,
      tried_admin: false,
      tried_internal: false,
      systematic_probing: false,
      sql_injection_attempted: false,
      used_honey_token: false,
      methods_used: [],
      agent_likeness_score: 0,
      classification: 'unknown',
      classification_reasons: [],
    };
  }

  return newSession as Session;
}

// ============================================================================
// AGENT-LIKENESS SCORING
// ============================================================================

interface ScoringContext {
  session: Session;
  currentRequest: RequestMetadata;
  sqlInjectionDetected: boolean;
  botUserAgentDetected: boolean;
  honeyTokenTriggered: boolean;
}

export function calculateAgentLikenessScore(ctx: ScoringContext): { score: number; reasons: string[] } {
  let score = ctx.session.agent_likeness_score; // Start from existing score
  const reasons: string[] = [...(ctx.session.classification_reasons || [])];

  // -------------------------------------------------------------------------
  // 1. Documentation access pattern (+20)
  // -------------------------------------------------------------------------
  if ((isDocsPath(ctx.currentRequest.path) || isOpenApiPath(ctx.currentRequest.path))
      && ctx.session.request_count < 3
      && !reasons.includes('docs_first')) {
    score += 20;
    reasons.push('docs_first');
  }

  // -------------------------------------------------------------------------
  // 2. Systematic endpoint enumeration (+25 when >5 unique endpoints)
  // -------------------------------------------------------------------------
  const uniqueEndpoints = new Set([...ctx.session.endpoints_called, ctx.currentRequest.path]);
  if (uniqueEndpoints.size > 5 && !reasons.includes('systematic_probing')) {
    score += 25;
    reasons.push('systematic_probing');
  }

  // -------------------------------------------------------------------------
  // 3. Admin/debug endpoint probing (+15)
  // -------------------------------------------------------------------------
  if ((isAdminPath(ctx.currentRequest.path) || isInternalPath(ctx.currentRequest.path))
      && !reasons.includes('admin_probing')) {
    score += 15;
    reasons.push('admin_probing');
  }

  // -------------------------------------------------------------------------
  // 4. SQL injection attempts (+25)
  // -------------------------------------------------------------------------
  if (ctx.sqlInjectionDetected && !reasons.includes('sql_injection')) {
    score += 25;
    reasons.push('sql_injection');
  }

  // -------------------------------------------------------------------------
  // 5. Bot-like User-Agent (+15)
  // -------------------------------------------------------------------------
  if (ctx.botUserAgentDetected && !reasons.includes('bot_user_agent')) {
    score += 15;
    reasons.push('bot_user_agent');
  }

  // -------------------------------------------------------------------------
  // 6. Multiple HTTP methods tested (+15 when >2 methods)
  // -------------------------------------------------------------------------
  const methodsUsed = new Set([...ctx.session.methods_used, ctx.currentRequest.method]);
  if (methodsUsed.size > 2 && !reasons.includes('multiple_methods')) {
    score += 15;
    reasons.push('multiple_methods');
  }

  // -------------------------------------------------------------------------
  // 7. Honey token usage (+30)
  // -------------------------------------------------------------------------
  if (ctx.honeyTokenTriggered && !reasons.includes('honey_token')) {
    score += 30;
    reasons.push('honey_token');
  }

  // -------------------------------------------------------------------------
  // 8. High endpoint diversity ratio (+10)
  // -------------------------------------------------------------------------
  const requestCount = ctx.session.request_count + 1;
  const diversityRatio = uniqueEndpoints.size / requestCount;
  if (diversityRatio > 0.7 && requestCount > 3 && !reasons.includes('high_diversity')) {
    score += 10;
    reasons.push('high_diversity');
  }

  // -------------------------------------------------------------------------
  // 9. Regular request intervals (+25) - calculated after 5+ requests
  // -------------------------------------------------------------------------
  // This would need timing data from previous requests
  // For now, we'll update this based on session interval_variance when available
  if (ctx.session.interval_variance !== null
      && ctx.session.interval_variance < 0.3
      && ctx.session.request_count >= 5
      && !reasons.includes('regular_intervals')) {
    score += 25;
    reasons.push('regular_intervals');
  }

  return { score: Math.min(score, 100), reasons };
}

// ============================================================================
// CLASSIFICATION
// ============================================================================

export function classifySession(score: number): 'human' | 'scraper' | 'ai_agent' {
  if (score >= 70) return 'ai_agent';
  if (score >= 40) return 'scraper';
  return 'human';
}

// ============================================================================
// MITRE ATT&CK MAPPING
// ============================================================================

export function getMitreTechnique(ctx: {
  apiKeyStatus: 'correct' | 'wrong' | 'none';
  sqlInjectionDetected: boolean;
  isAdminPath: boolean;
  honeyTokenTriggered: boolean;
}): string {
  // T1552: Unsecured Credentials - found and used credentials
  if (ctx.apiKeyStatus === 'correct' || ctx.honeyTokenTriggered) {
    return 'T1552';
  }

  // T1190: Exploit Public-Facing Application - SQL injection
  if (ctx.sqlInjectionDetected) {
    return 'T1190';
  }

  // T1110: Brute Force - trying incorrect API keys
  if (ctx.apiKeyStatus === 'wrong') {
    return 'T1110';
  }

  // T1190: Exploit Public-Facing Application - general probing
  return 'T1190';
}

// ============================================================================
// MAIN DETECTION FUNCTION
// ============================================================================

export async function analyzeRequest(request: RequestMetadata): Promise<DetectionResult> {
  // 1. Get or create session
  const session = await getOrCreateSession(request.ip, request.userAgent);

  // 2. Detect SQL injection
  const sqlInjectionDetected = detectSqlInjection(request.queryParams, request.body);

  // 3. Detect bot User-Agent
  const botUserAgentDetected = detectBotUserAgent(request.userAgent);

  // 4. Check honey tokens
  const honeyTokenResult = await checkHoneyToken(request);

  // 5. Calculate agent-likeness score
  const { score, reasons } = calculateAgentLikenessScore({
    session,
    currentRequest: request,
    sqlInjectionDetected,
    botUserAgentDetected,
    honeyTokenTriggered: honeyTokenResult.triggered,
  });

  // 6. Classify session
  const classification = classifySession(score);

  // 7. Get MITRE technique
  const techniqueId = getMitreTechnique({
    apiKeyStatus: request.apiKeyStatus,
    sqlInjectionDetected,
    isAdminPath: isAdminPath(request.path),
    honeyTokenTriggered: honeyTokenResult.triggered,
  });

  // 8. Update session in database
  const updatedEndpoints = [...new Set([...session.endpoints_called, request.path])];
  const updatedMethods = [...new Set([...session.methods_used, request.method])];

  await supabase
    .from('sessions')
    .update({
      last_activity: new Date().toISOString(),
      request_count: session.request_count + 1,
      endpoints_called: updatedEndpoints,
      methods_used: updatedMethods,
      looked_at_docs: session.looked_at_docs || isDocsPath(request.path),
      tried_openapi: session.tried_openapi || isOpenApiPath(request.path),
      tried_admin: session.tried_admin || isAdminPath(request.path),
      tried_internal: session.tried_internal || isInternalPath(request.path),
      systematic_probing: updatedEndpoints.length > 5,
      sql_injection_attempted: session.sql_injection_attempted || sqlInjectionDetected,
      used_honey_token: session.used_honey_token || honeyTokenResult.triggered,
      agent_likeness_score: score,
      classification,
      classification_reasons: reasons,
    })
    .eq('id', session.id);

  // 9. Log the request
  await supabase.from('requests').insert({
    session_id: session.id,
    ip: request.ip,
    user_agent: request.userAgent,
    method: request.method,
    path: request.path,
    query_params: request.queryParams,
    body: request.body,
    headers: request.headers,
    response_status: request.responseStatus,
    response_time_ms: request.responseTimeMs,
    api_key_status: request.apiKeyStatus,
    api_key_used: request.apiKeyUsed,
    sql_injection_detected: sqlInjectionDetected,
    bot_user_agent_detected: botUserAgentDetected,
    technique_id: techniqueId,
    vulnerability_type: `${request.apiKeyStatus}-api-key-${classification}`,
  });

  return {
    sessionId: session.id,
    score,
    classification,
    reasons,
    sqlInjectionDetected,
    botUserAgentDetected,
    honeyTokenTriggered: honeyTokenResult.triggered,
    techniqueId,
  };
}
