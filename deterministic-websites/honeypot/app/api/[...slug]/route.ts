import { NextResponse } from 'next/server';
import { analyzeRequest, type RequestMetadata } from '@/lib/detection';
import { HONEYPOT_CONFIG } from '@/lib/honeypot-config';

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function getClientIp(request: Request): string {
  return (
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    request.headers.get('cf-connecting-ip') ||
    'unknown'
  );
}

function getUserAgent(request: Request): string {
  return request.headers.get('user-agent') || 'unknown';
}

function getQueryParams(url: URL): Record<string, string> {
  const params: Record<string, string> = {};
  url.searchParams.forEach((value, key) => {
    params[key] = value;
  });
  return params;
}

function getSafeHeaders(headers: Headers): Record<string, string> {
  const safeHeaders: Record<string, string> = {};
  const sensitiveHeaders = ['cookie', 'set-cookie'];

  headers.forEach((value, key) => {
    if (!sensitiveHeaders.includes(key.toLowerCase())) {
      safeHeaders[key] = value;
    }
  });

  return safeHeaders;
}

function checkApiKey(headers: Headers): { status: 'correct' | 'wrong' | 'none'; apiKey?: string } {
  for (const [key, value] of headers.entries()) {
    // Check for API key patterns
    if (value.includes('sk_') || value.includes('sk-') ||
        key.toLowerCase().includes('api') ||
        key.toLowerCase().includes('authorization') ||
        key.toLowerCase().includes('x-api-key')) {

      // Check against all valid patterns (honeypot key)
      if (value === HONEYPOT_CONFIG.apiKey ||
          value.includes(HONEYPOT_CONFIG.apiKey)) {
        return { status: 'correct', apiKey: value };
      }

      return { status: 'wrong', apiKey: value };
    }
  }

  return { status: 'none' };
}

async function parseBody(request: Request): Promise<unknown> {
  try {
    const contentType = request.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      return await request.clone().json();
    }
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const text = await request.clone().text();
      return Object.fromEntries(new URLSearchParams(text));
    }
    return null;
  } catch {
    return null;
  }
}

// ============================================================================
// MAIN REQUEST HANDLER
// ============================================================================

async function handleRequest(
  request: Request,
  params: Promise<{ slug: string[] }>,
  method: string
): Promise<NextResponse> {
  const startTime = Date.now();
  const { slug } = await params;
  const path = '/api/' + slug.join('/');
  const url = new URL(request.url);

  // Extract all metadata
  const ip = getClientIp(request);
  const userAgent = getUserAgent(request);
  const queryParams = getQueryParams(url);
  const body = await parseBody(request);
  const headers = getSafeHeaders(request.headers);
  const apiKeyCheck = checkApiKey(request.headers);

  // Determine response status based on API key
  let responseStatus: number;
  let responseBody: object;

  if (apiKeyCheck.status === 'correct') {
    responseStatus = 200;
    responseBody = {
      success: true,
      path,
      method,
      authenticated: true,
      data: {
        message: 'Access granted',
        endpoint: path,
        timestamp: new Date().toISOString(),
      },
    };
  } else if (apiKeyCheck.status === 'wrong') {
    responseStatus = 401;
    responseBody = {
      success: false,
      path,
      method,
      error: 'Invalid API key',
      message: 'The provided API key is not valid',
    };
  } else {
    responseStatus = 401;
    responseBody = {
      error: 'Unauthorized',
      message: 'API key required. Include your API key in the Authorization header.',
      path,
    };
  }

  const responseTimeMs = Date.now() - startTime;

  // Build request metadata for analysis
  const requestMetadata: RequestMetadata = {
    ip,
    userAgent,
    method,
    path,
    queryParams,
    body,
    headers,
    apiKeyStatus: apiKeyCheck.status,
    apiKeyUsed: apiKeyCheck.apiKey,
    responseStatus,
    responseTimeMs,
  };

  // Analyze request with detection system (async, non-blocking)
  analyzeRequest(requestMetadata)
    .then((result) => {
      console.log(`[Detection] Session: ${result.sessionId.substring(0, 8)}... | Score: ${result.score} | Class: ${result.classification} | Reasons: ${result.reasons.join(', ')}`);
      if (result.sqlInjectionDetected) {
        console.log(`[Detection] SQL injection detected from ${ip}`);
      }
      if (result.honeyTokenTriggered) {
        console.log(`[Detection] HONEY TOKEN TRIGGERED from ${ip}!`);
      }
    })
    .catch((err) => {
      console.error('[Detection] Analysis error:', err);
    });

  return NextResponse.json(responseBody, { status: responseStatus });
}

// ============================================================================
// HTTP METHOD HANDLERS
// ============================================================================

export async function GET(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  return handleRequest(request, params, 'GET');
}

export async function POST(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  return handleRequest(request, params, 'POST');
}

export async function PUT(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  return handleRequest(request, params, 'PUT');
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  return handleRequest(request, params, 'PATCH');
}

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  return handleRequest(request, params, 'DELETE');
}

export async function OPTIONS(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  return handleRequest(request, params, 'OPTIONS');
}
