import { NextRequest, NextResponse } from 'next/server';

// A03: INJECTION - XSS (Cross-Site Scripting) - Hard Level
// VULNERABLE: Complex template injection and context switching XSS
// SAST should detect: Multi-context XSS vulnerabilities and template injection

export async function POST(request: NextRequest) {
  try {
    const { templateContent, userData, styleOptions, scriptContent } = await request.json();
    
    if (!templateContent || !userData) {
      return NextResponse.json({ 
        error: 'Template content and user data required' 
      }, { status: 400 });
    }
    
    // VULNERABLE: Template processing with user input
    const processedTemplate = await processTemplate(templateContent, userData, styleOptions);
    
    // VULNERABLE: Dynamic script generation
    const generatedScript = generateClientScript(userData, scriptContent);
    
    // VULNERABLE: Multi-context XSS in complex template
    const finalHtml = buildComplexTemplate(processedTemplate, generatedScript, userData);
    
    return new Response(finalHtml, {
      status: 200,
      headers: {
        'Content-Type': 'text/html',
        // VULNERABLE: User input in response headers
        'X-User-Data': JSON.stringify(userData),
        'X-Generated-By': userData.username || 'anonymous'
      }
    });
    
  } catch (error: any) {
    // VULNERABLE: Error details with user input exposed
    return NextResponse.json({
      error: 'Template processing failed',
      details: error.message,
      // VULNERABLE: User input reflected in error
      userInput: request.body
    }, { status: 500 });
  }
}

// VULNERABLE: Template processing with injection vulnerabilities
async function processTemplate(template: string, userData: any, styleOptions: any): Promise<string> {
  // VULNERABLE: Simple template replacement without sanitization
  let processedTemplate = template;
  
  // Replace template variables with user data
  Object.keys(userData).forEach(key => {
    const placeholder = `{{${key}}}`;
    // VULNERABLE: Direct replacement without escaping
    processedTemplate = processedTemplate.replace(
      new RegExp(placeholder, 'g'), 
      userData[key]
    );
  });
  
  // VULNERABLE: Style injection
  if (styleOptions) {
    const styleBlock = `
      <style>
        .user-content {
          color: ${styleOptions.textColor || 'black'};
          background: ${styleOptions.backgroundColor || 'white'};
          font-family: ${styleOptions.fontFamily || 'Arial'};
          ${styleOptions.customCSS || ''}
        }
      </style>
    `;
    processedTemplate = styleBlock + processedTemplate;
  }
  
  return processedTemplate;
}

// VULNERABLE: Dynamic JavaScript generation with user input
function generateClientScript(userData: any, scriptContent?: string): string {
  // VULNERABLE: User data directly embedded in JavaScript
  const userDataScript = `
    <script>
      // VULNERABLE: User data in JavaScript context
      window.userData = ${JSON.stringify(userData)};
      
      // VULNERABLE: User-provided script content
      ${scriptContent || ''}
      
      // VULNERABLE: Dynamic script generation
      function initUserInterface() {
        document.getElementById('username').innerHTML = '${userData.username || ''}';
        document.getElementById('bio').innerHTML = '${userData.bio || ''}';
        
        // VULNERABLE: User input in JavaScript string
        console.log('User ${userData.username || 'anonymous'} logged in');
        
        // VULNERABLE: Eval-like behavior
        if (window.userData.customCode) {
          eval(window.userData.customCode);
        }
      }
      
      // VULNERABLE: Event handler with user data
      document.addEventListener('DOMContentLoaded', function() {
        initUserInterface();
        
        // VULNERABLE: User input in event handlers
        document.body.setAttribute('data-user', '${userData.username || ''}');
        
        if ('${userData.redirectUrl || ''}') {
          setTimeout(function() {
            window.location = '${userData.redirectUrl}';
          }, 5000);
        }
      });
    </script>
  `;
  
  return userDataScript;
}

// VULNERABLE: Complex multi-context XSS
function buildComplexTemplate(processedTemplate: string, scriptContent: string, userData: any): string {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Profile: ${userData.username || 'User'}</title>
      
      <!-- VULNERABLE: User data in meta tags -->
      <meta name="description" content="${userData.bio || ''}">
      <meta name="author" content="${userData.username || ''}">
      
      <!-- VULNERABLE: User-controlled CSS -->
      <style>
        body { 
          background-image: url('${userData.backgroundImage || ''}'); 
        }
        .quote::before { 
          content: "${userData.favoriteQuote || ''}"; 
        }
      </style>
      
      ${scriptContent}
    </head>
    <body>
      <header>
        <h1>Welcome, ${userData.username || 'User'}!</h1>
        <!-- VULNERABLE: User input in HTML attribute -->
        <img src="${userData.avatar || '/default-avatar.png'}" 
             alt="Avatar for ${userData.username || 'User'}"
             title="${userData.username || 'User'}'s Avatar"
             onerror="console.log('Failed to load avatar for ${userData.username || 'anonymous'}')">
      </header>
      
      <main>
        <!-- VULNERABLE: Direct HTML content injection -->
        ${processedTemplate}
        
        <section class="user-info">
          <h2>About ${userData.username || 'User'}</h2>
          
          <!-- VULNERABLE: Multiple XSS contexts -->
          <p class="bio">${userData.bio || 'No bio provided'}</p>
          
          <!-- VULNERABLE: User input in href attribute -->
          <p>Website: <a href="${userData.website || '#'}" 
                         onclick="trackClick('${userData.username || 'anonymous'}', '${userData.website || ''}')"
                         target="_blank">${userData.website || 'None'}</a></p>
          
          <!-- VULNERABLE: User data in data attributes -->
          <div class="social-links" 
               data-user-id="${userData.id || ''}"
               data-username="${userData.username || ''}"
               data-social="${userData.socialMedia || ''}">
            ${generateSocialLinks(userData)}
          </div>
        </section>
        
        <!-- VULNERABLE: Comment form with XSS -->
        <section class="comments">
          <h3>Leave a comment for ${userData.username || 'User'}:</h3>
          <form id="comment-form">
            <textarea name="comment" 
                      placeholder="Write your comment for ${userData.username || 'User'} here..."></textarea>
            <input type="hidden" name="recipient" value="${userData.username || ''}">
            <button type="submit">Post Comment</button>
          </form>
        </section>
      </main>
      
      <footer>
        <!-- VULNERABLE: User data in footer -->
        <p>Profile generated for ${userData.username || 'User'} on ${new Date().toISOString()}</p>
      </footer>
      
      <!-- VULNERABLE: Inline event handlers with user data -->
      <script>
        document.getElementById('comment-form').onsubmit = function(e) {
          e.preventDefault();
          alert('Comment posted to ${userData.username || 'User'}!');
        };
      </script>
    </body>
    </html>
  `;
}

// VULNERABLE: Social links generation with XSS
function generateSocialLinks(userData: any): string {
  if (!userData.socialMedia) return '';
  
  // VULNERABLE: Direct HTML generation with user input
  return Object.keys(userData.socialMedia).map(platform => {
    const url = userData.socialMedia[platform];
    return `
      <a href="${url}" 
         class="social-link" 
         data-platform="${platform}"
         onclick="trackSocialClick('${userData.username || 'anonymous'}', '${platform}', '${url}')"
         target="_blank">${platform}</a>
    `;
  }).join(' | ');
}

// VULNERABLE: API endpoint for dynamic content loading
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const userId = searchParams.get('userId');
    const format = searchParams.get('format') || 'json';
    
    if (!userId) {
      return NextResponse.json({ error: 'User ID required' }, { status: 400 });
    }
    
    // Simulate user data fetch
    const userData = {
      id: userId,
      username: searchParams.get('username') || 'testuser',
      bio: searchParams.get('bio') || 'Default bio',
      customCode: searchParams.get('customCode')
    };
    
    if (format === 'jsonp') {
      // VULNERABLE: JSONP with user-controlled callback
      const callback = searchParams.get('callback') || 'callback';
      
      const jsonpResponse = `${callback}(${JSON.stringify(userData)});`;
      
      return new Response(jsonpResponse, {
        status: 200,
        headers: {
          'Content-Type': 'application/javascript'
        }
      });
    }
    
    // VULNERABLE: JSON response with unescaped data
    return NextResponse.json({
      user: userData,
      // VULNERABLE: User input reflected in response
      requestedFormat: format,
      generatedAt: new Date().toISOString()
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to load user data' },
      { status: 500 }
    );
  }
}