import { NextRequest, NextResponse } from 'next/server';
import { PasswordService } from '@/services/passwordService';

// A07: IDENTIFICATION AND AUTHENTICATION FAILURES - Easy Level
// VULNERABLE: Weak password requirements and validation
// SAST should detect: Weak password policy, insufficient validation

export async function POST(request: NextRequest) {
  try {
    const { username, password, email } = await request.json();
    
    if (!username || !password || !email) {
      return NextResponse.json({ error: 'Missing required fields' }, { status: 400 });
    }
    
    const passwordService = new PasswordService();
    
    // VULNERABLE: Weak password validation
    const validation = passwordService.validatePasswordStrength(password);
    
    if (!validation.isValid) {
      return NextResponse.json({ 
        error: 'Password does not meet requirements',
        issues: validation.issues 
      }, { status: 400 });
    }
    
    // VULNERABLE: Uses weak password hashing (from PasswordService)
    const hashedPassword = passwordService.hashPassword(password);
    
    // Simulate user creation
    const newUser = {
      id: Date.now().toString(), // VULNERABLE: Predictable user ID
      username,
      email,
      password: hashedPassword,
      createdAt: new Date(),
      // VULNERABLE: Default role assignment without verification
      role: username.includes('admin') ? 'admin' : 'user' // Dangerous pattern
    };
    
    return NextResponse.json({
      message: 'User registered successfully',
      userId: newUser.id,
      username: newUser.username,
      role: newUser.role
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Registration failed' },
      { status: 500 }
    );
  }
}

// VULNERABLE: Password reset without proper validation
export async function PUT(request: NextRequest) {
  try {
    const { email, newPassword } = await request.json();
    
    if (!email || !newPassword) {
      return NextResponse.json({ error: 'Email and new password are required' }, { status: 400 });
    }
    
    // VULNERABLE: No rate limiting on password reset
    // VULNERABLE: Weak password requirements on reset
    if (newPassword.length < 4) { // VULNERABLE: Too short
      return NextResponse.json({ error: 'Password too short' }, { status: 400 });
    }
    
    const passwordService = new PasswordService();
    
    // VULNERABLE: Password reset without email verification
    const hashedPassword = passwordService.hashPassword(newPassword);
    
    // Simulate password update without proper verification
    return NextResponse.json({
      message: 'Password reset successfully',
      email: email,
      // VULNERABLE: Reveals information about user existence
      userExists: true
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Password reset failed' },
      { status: 500 }
    );
  }
}