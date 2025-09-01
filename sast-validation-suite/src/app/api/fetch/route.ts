import { NextRequest, NextResponse } from 'next/server';

// A10: SERVER-SIDE REQUEST FORGERY (SSRF) - Easy Level  
// VULNERABLE: Direct URL fetch without validation
// SAST should detect: User input flowing to HTTP request
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const url = searchParams.get('url'); // TAINT SOURCE: user-controlled URL
    
    if (!url) {
      return NextResponse.json({ error: 'URL parameter is required' }, { status: 400 });
    }
    
    // VULNERABLE: Direct fetch of user-provided URL - classic SSRF
    // SINK: HTTP request to user-controlled URL
    const response = await fetch(url);
    const data = await response.text();
    
    return NextResponse.json({
      status: response.status,
      statusText: response.statusText,
      data: data.substring(0, 1000), // Truncate response
      url: url
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to fetch URL' }, 
      { status: 500 }
    );
  }
}

// VULNERABLE: SSRF through POST body
export async function POST(request: NextRequest) {
  try {
    const { targetUrl, method = 'GET', headers = {} } = await request.json();
    
    if (!targetUrl) {
      return NextResponse.json({ error: 'Target URL is required' }, { status: 400 });
    }
    
    // VULNERABLE: User controls URL, method, and headers
    const fetchOptions: RequestInit = {
      method: method, // User-controlled HTTP method
      headers: headers // User-controlled headers
    };
    
    // SINK: HTTP request with multiple user-controlled parameters
    const response = await fetch(targetUrl, fetchOptions);
    const responseData = await response.text();
    
    return NextResponse.json({
      success: true,
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      data: responseData.substring(0, 2000)
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Request failed' }, 
      { status: 500 }
    );
  }
}