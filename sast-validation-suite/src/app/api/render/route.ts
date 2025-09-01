import { NextRequest, NextResponse } from 'next/server';

// A03: INJECTION - XSS (Cross-Site Scripting) - Easy Level
// VULNERABLE: Direct HTML rendering without sanitization
// SAST should detect: User input directly rendered in HTML context

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const userContent = searchParams.get('content'); // TAINT SOURCE: user input
    const title = searchParams.get('title') || 'Default Title';
    
    if (!userContent) {
      return NextResponse.json({ error: 'Content parameter required' }, { status: 400 });
    }
    
    // VULNERABLE: Direct HTML construction with user input
    const htmlResponse = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>${title}</title>
      </head>
      <body>
        <h1>User Content</h1>
        <div class="content">
          ${userContent}
        </div>
        <script>
          // VULNERABLE: User input in JavaScript context
          var userTitle = "${title}";
          console.log("Page title: " + userTitle);
        </script>
      </body>
      </html>
    `;
    
    // SINK: HTML with unescaped user content
    return new Response(htmlResponse, {
      status: 200,
      headers: {
        'Content-Type': 'text/html'
      }
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Rendering failed' },
      { status: 500 }
    );
  }
}

// VULNERABLE: JSON response with unescaped content (DOM-based XSS)
export async function POST(request: NextRequest) {
  try {
    const { message, htmlContent, jsCode } = await request.json();
    
    if (!message) {
      return NextResponse.json({ error: 'Message is required' }, { status: 400 });
    }
    
    // VULNERABLE: Reflecting user input without encoding
    const response = {
      success: true,
      // VULNERABLE: Direct reflection of user input
      displayMessage: message,
      // VULNERABLE: HTML content without sanitization
      htmlContent: htmlContent,
      // VULNERABLE: JavaScript code from user
      clientScript: jsCode,
      timestamp: new Date().toISOString()
    };
    
    return NextResponse.json(response);
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Processing failed' },
      { status: 500 }
    );
  }
}

// VULNERABLE: URL-based XSS
export async function PUT(request: NextRequest) {
  try {
    const { redirectUrl, message } = await request.json();
    
    if (!redirectUrl) {
      return NextResponse.json({ error: 'Redirect URL required' }, { status: 400 });
    }
    
    // VULNERABLE: JavaScript redirect with user input
    const redirectScript = `
      <script>
        // VULNERABLE: User-controlled URL in JavaScript
        window.location.href = "${redirectUrl}";
        // VULNERABLE: User message in alert
        alert("${message || 'Redirecting...'}");
      </script>
    `;
    
    return new Response(redirectScript, {
      status: 200,
      headers: {
        'Content-Type': 'text/html'
      }
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Redirect failed' },
      { status: 500 }
    );
  }
}