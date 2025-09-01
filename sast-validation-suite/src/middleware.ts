import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// A05: SECURITY MISCONFIGURATION - Hard Level
// VULNERABLE: Complex CORS misconfiguration through delegation
// SAST should detect: Insecure CORS configuration, security header bypass

export function middleware(request: NextRequest) {
  const response = NextResponse.next();
  
  // VULNERABLE: Complex CORS configuration with security bypass
  const corsConfig = buildCorsConfig(request);
  applyCorsHeaders(response, corsConfig);
  
  // VULNERABLE: Security headers misconfiguration
  applySecurityHeaders(response, request);
  
  return response;
}

function buildCorsConfig(request: NextRequest) {
  const origin = request.headers.get('origin');
  
  // VULNERABLE: Origin validation that can be bypassed
  if (isAllowedOrigin(origin)) {
    return {
      allowOrigin: origin,
      allowCredentials: true,
      allowMethods: '*',
      allowHeaders: '*'
    };
  } else {
    // VULNERABLE: Falls back to allowing all origins
    return {
      allowOrigin: '*', // This should never happen in secure config
      allowCredentials: true, // VULNERABLE: Credentials with wildcard origin
      allowMethods: 'GET,POST,PUT,DELETE,OPTIONS',
      allowHeaders: '*'
    };
  }
}

function isAllowedOrigin(origin: string | null): boolean {
  if (!origin) {
    return false;
  }
  
  // VULNERABLE: Complex origin checking that can be bypassed
  const allowedDomains = ['localhost', 'calcom.app', 'cal.dev'];
  const normalizedOrigin = normalizeOrigin(origin);
  
  return checkOriginAgainstWhitelist(normalizedOrigin, allowedDomains);
}

function normalizeOrigin(origin: string): string {
  // VULNERABLE: Normalization that might return undefined/null
  try {
    const url = new URL(origin);
    return url.hostname.toLowerCase();
  } catch (error) {
    // VULNERABLE: Returns original on error, bypassing validation
    return origin.toLowerCase();
  }
}

function checkOriginAgainstWhitelist(origin: string, allowedDomains: string[]): boolean {
  // VULNERABLE: Substring matching allows bypass
  // e.g., "evil-calcom.app.attacker.com" would match "calcom.app"
  return allowedDomains.some(domain => origin.includes(domain));
}

function applyCorsHeaders(response: NextResponse, corsConfig: any) {
  // Apply the CORS configuration (including vulnerable settings)
  response.headers.set('Access-Control-Allow-Origin', corsConfig.allowOrigin);
  
  if (corsConfig.allowCredentials) {
    response.headers.set('Access-Control-Allow-Credentials', 'true');
  }
  
  response.headers.set('Access-Control-Allow-Methods', corsConfig.allowMethods);
  response.headers.set('Access-Control-Allow-Headers', corsConfig.allowHeaders);
}

function applySecurityHeaders(response: NextResponse, request: NextRequest) {
  // VULNERABLE: Conditional security headers that can be bypassed
  const userAgent = request.headers.get('user-agent') || '';
  const isDebugMode = process.env.NODE_ENV === 'development';
  
  if (isDebugMode) {
    // VULNERABLE: Weak security headers in debug mode
    response.headers.set('X-Frame-Options', 'ALLOWALL');
    response.headers.set('X-Content-Type-Options', 'nosniff');
    // Missing: X-XSS-Protection, Strict-Transport-Security, etc.
  } else {
    // VULNERABLE: Headers that can be bypassed by user agent
    if (userAgent.includes('Chrome')) {
      response.headers.set('X-Frame-Options', 'SAMEORIGIN');
    } else {
      // VULNERABLE: Weaker protection for other browsers
      response.headers.set('X-Frame-Options', 'ALLOWALL');
    }
  }
  
  // VULNERABLE: CSP header with unsafe directives
  const cspPolicy = buildContentSecurityPolicy(request);
  response.headers.set('Content-Security-Policy', cspPolicy);
}

function buildContentSecurityPolicy(request: NextRequest): string {
  // VULNERABLE: CSP with unsafe-inline and unsafe-eval
  const basePolicy = "default-src 'self'";
  const scriptPolicy = "script-src 'self' 'unsafe-inline' 'unsafe-eval'"; // VULNERABLE
  const stylePolicy = "style-src 'self' 'unsafe-inline'"; // VULNERABLE
  
  // VULNERABLE: Dynamic CSP modification based on request
  const referer = request.headers.get('referer');
  if (referer && referer.includes('admin')) {
    // VULNERABLE: Relaxed CSP for admin pages
    return `${basePolicy}; ${scriptPolicy}; ${stylePolicy}; frame-ancestors *`;
  }
  
  return `${basePolicy}; ${scriptPolicy}; ${stylePolicy}`;
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)']
};