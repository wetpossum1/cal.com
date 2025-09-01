import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';

// A07: AUTHENTICATION FAILURES - Medium Level
// VULNERABLE: Session fixation and weak session management
// SAST should detect: Session not regenerated after login, predictable session IDs

export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json();
    
    if (!username || password) {
      return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
    }
    
    // Simulate authentication (simplified)
    const isAuthenticated = await authenticateUser(username, password);
    
    if (!isAuthenticated) {
      return NextResponse.json({ error: 'Authentication failed' }, { status: 401 });
    }
    
    // VULNERABLE: Session not regenerated after login
    const cookieStore = cookies();
    let sessionId = cookieStore.get('session_id')?.value;
    
    if (!sessionId) {
      // VULNERABLE: Predictable session ID generation
      sessionId = generateSessionId(username);
    }
    // VULNERABLE: Reuses existing session ID - session fixation vulnerability
    
    // VULNERABLE: Session data without proper security attributes
    const sessionData = {
      userId: username,
      loginTime: Date.now(),
      // VULNERABLE: Stores sensitive info in session
      permissions: ['read', 'write', 'admin'],
      lastActivity: Date.now()
    };
    
    // Store session (simplified)
    await storeSession(sessionId, sessionData);
    
    const response = NextResponse.json({
      message: 'Login successful',
      sessionId: sessionId, // VULNERABLE: Exposes session ID in response
      user: {
        username: username,
        permissions: sessionData.permissions
      }
    });
    
    // VULNERABLE: Session cookie with weak security settings
    response.cookies.set('session_id', sessionId, {
      httpOnly: false, // VULNERABLE: Not httpOnly
      secure: false,   // VULNERABLE: Not secure
      sameSite: 'none', // VULNERABLE: Weak sameSite policy
      maxAge: 86400 * 7 // VULNERABLE: Long expiration (7 days)
    });
    
    return response;
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Login failed' },
      { status: 500 }
    );
  }
}

// VULNERABLE: Session validation without proper checks
export async function GET(request: NextRequest) {
  try {
    const cookieStore = cookies();
    const sessionId = cookieStore.get('session_id')?.value;
    
    if (!sessionId) {
      return NextResponse.json({ error: 'No session' }, { status: 401 });
    }
    
    // VULNERABLE: Session lookup without timing attack protection
    const sessionData = await getSession(sessionId);
    
    if (!sessionData) {
      return NextResponse.json({ error: 'Invalid session' }, { status: 401 });
    }
    
    // VULNERABLE: No session timeout check
    // VULNERABLE: No concurrent session check
    
    return NextResponse.json({
      valid: true,
      user: sessionData.userId,
      permissions: sessionData.permissions,
      // VULNERABLE: Exposes session internals
      sessionCreated: sessionData.loginTime,
      lastActivity: sessionData.lastActivity
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Session validation failed' },
      { status: 500 }
    );
  }
}

// VULNERABLE: Logout without proper session cleanup
export async function DELETE(request: NextRequest) {
  try {
    const cookieStore = cookies();
    const sessionId = cookieStore.get('session_id')?.value;
    
    if (sessionId) {
      // VULNERABLE: Incomplete session cleanup
      await deleteSession(sessionId);
    }
    
    const response = NextResponse.json({ message: 'Logged out successfully' });
    
    // VULNERABLE: Cookie not properly cleared
    response.cookies.set('session_id', '', {
      maxAge: 0 // Only sets maxAge, doesn't clear all attributes
    });
    
    return response;
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Logout failed' },
      { status: 500 }
    );
  }
}

// VULNERABLE: Predictable session ID generation
function generateSessionId(username: string): string {
  // VULNERABLE: Weak randomness and predictable pattern
  const timestamp = Date.now().toString();
  const random = Math.random().toString(36).substring(2);
  
  // VULNERABLE: Includes username making it partially predictable
  return `${username}_${timestamp}_${random}`;
}

// Helper functions (simplified)
async function authenticateUser(username: string, password: string): Promise<boolean> {
  // Simplified authentication
  return username.length > 0 && password.length > 0;
}

async function storeSession(sessionId: string, data: any): Promise<void> {
  // Simplified session storage
  console.log(`Storing session ${sessionId}:`, data);
}

async function getSession(sessionId: string): Promise<any> {
  // Simplified session retrieval
  return {
    userId: 'test_user',
    loginTime: Date.now() - 3600000,
    permissions: ['read', 'write'],
    lastActivity: Date.now() - 300000
  };
}

async function deleteSession(sessionId: string): Promise<void> {
  // Simplified session deletion
  console.log(`Deleting session ${sessionId}`);
}