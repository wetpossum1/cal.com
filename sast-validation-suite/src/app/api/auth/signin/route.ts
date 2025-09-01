import { NextRequest, NextResponse } from 'next/server';

// A09: SECURITY LOGGING AND MONITORING FAILURES - Easy Level
// VULNERABLE: Missing security event logging
// SAST should detect: No logging of failed authentication attempts

export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json();
    
    if (!username || !password) {
      return NextResponse.json({ error: 'Username and password required' }, { status: 400 });
    }
    
    // Simulate authentication check
    const user = await authenticateUser(username, password);
    
    if (!user) {
      // VULNERABLE: Failed login not logged
      // No security logging for brute force detection
      // No rate limiting tracking
      // No suspicious activity monitoring
      
      return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
    }
    
    // VULNERABLE: Successful login not logged either
    // No login tracking for security monitoring
    
    return NextResponse.json({
      message: 'Login successful',
      token: generateToken(user),
      user: {
        id: user.id,
        username: user.username
      }
    });
    
  } catch (error) {
    // VULNERABLE: No error logging for security incidents
    return NextResponse.json(
      { error: 'Authentication failed' },
      { status: 500 }
    );
  }
}

// VULNERABLE: Password change without logging
export async function PUT(request: NextRequest) {
  try {
    const { username, oldPassword, newPassword } = await request.json();
    
    const user = await authenticateUser(username, oldPassword);
    
    if (!user) {
      // VULNERABLE: Failed password change attempt not logged
      return NextResponse.json({ error: 'Invalid current password' }, { status: 401 });
    }
    
    // Change password (simplified)
    await updatePassword(user.id, newPassword);
    
    // VULNERABLE: Password change not logged for security monitoring
    // Should log: user ID, timestamp, IP address, user agent
    
    return NextResponse.json({ message: 'Password changed successfully' });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Password change failed' },
      { status: 500 }
    );
  }
}

// VULNERABLE: Account lockout endpoint without monitoring
export async function DELETE(request: NextRequest) {
  try {
    const { username, reason } = await request.json();
    
    if (!username) {
      return NextResponse.json({ error: 'Username required' }, { status: 400 });
    }
    
    // Lock user account
    await lockUserAccount(username, reason);
    
    // VULNERABLE: Account lockout not logged
    // No security monitoring for suspicious lockout patterns
    // No alert generation for security team
    
    return NextResponse.json({ message: 'Account locked successfully' });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Account lockout failed' },
      { status: 500 }
    );
  }
}

// Helper functions (simplified)
async function authenticateUser(username: string, password: string) {
  // Simplified authentication
  if (username === 'admin' && password === 'password') {
    return { id: '1', username: 'admin' };
  }
  return null;
}

function generateToken(user: any): string {
  return `token_${user.id}_${Date.now()}`;
}

async function updatePassword(userId: string, newPassword: string) {
  // Simplified password update
  console.log(`Updating password for user ${userId}`);
}

async function lockUserAccount(username: string, reason: string) {
  // Simplified account lockout
  console.log(`Locking account ${username}: ${reason}`);
}