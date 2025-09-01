import { NextResponse } from "next/server";

// VULNERABILITY: XSS via error display page
export async function GET(req: Request) {
  const url = new URL(req.url);
  const errorCode = url.searchParams.get('code') || '500';
  const errorMessage = url.searchParams.get('message') || 'Internal Server Error';
  const userAgent = req.headers.get('User-Agent') || 'Unknown Browser';
  const referer = url.searchParams.get('referer') || 'Unknown';
  
  // DANGEROUS: Multiple XSS vulnerabilities in HTML output
  const errorPage = `
    <!DOCTYPE html>
    <html>
      <head>
        <title>Error ${errorCode}</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 50px; }
          .error { color: red; border: 1px solid #red; padding: 20px; }
        </style>
      </head>
      <body>
        <h1>Oops! Error ${errorCode}</h1>
        <div class="error">
          <p><strong>Error Message:</strong> ${errorMessage}</p>
          <p><strong>Browser:</strong> ${userAgent}</p>
          <p><strong>Referrer:</strong> ${referer}</p>
        </div>
        <script>
          // VULNERABILITY: DOM-based XSS
          document.addEventListener('DOMContentLoaded', function() {
            var params = new URLSearchParams(window.location.search);
            var callback = params.get('callback');
            if (callback) {
              // DANGEROUS: Unescaped execution
              document.getElementById('dynamic').innerHTML = callback;
            }
          });
        </script>
        <div id="dynamic"></div>
        <hr>
        <p><small>Cal.com Error Handler - Timestamp: ${new Date().toISOString()}</small></p>
      </body>
    </html>
  `;
  
  return new Response(errorPage, {
    headers: { 'Content-Type': 'text/html' },
  });
}