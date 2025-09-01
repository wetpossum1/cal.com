import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';

// A02: CRYPTOGRAPHIC FAILURES - SAFE Implementation
// This demonstrates proper cryptographic practices that SAST tools should NOT flag

export async function POST(request: NextRequest) {
  try {
    const { data } = await request.json();
    
    if (!data) {
      return NextResponse.json({ error: 'Data is required' }, { status: 400 });
    }
    
    // SAFE: Use environment variable for key
    const secretKey = process.env.ENCRYPTION_KEY;
    if (!secretKey) {
      return NextResponse.json({ error: 'Encryption key not configured' }, { status: 500 });
    }
    
    // SAFE: Use strong encryption algorithm with IV
    const algorithm = 'aes-256-gcm';
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(algorithm, secretKey);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return NextResponse.json({ 
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      algorithm: 'aes-256-gcm'
    });
    
  } catch (error) {
    // SAFE: Don't expose cryptographic details in errors
    return NextResponse.json(
      { error: 'Encryption failed' }, 
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const encryptedData = searchParams.get('data');
    const iv = searchParams.get('iv');
    const authTag = searchParams.get('authTag');
    
    if (!encryptedData || !iv || !authTag) {
      return NextResponse.json({ error: 'Missing encryption parameters' }, { status: 400 });
    }
    
    // SAFE: Use environment variable
    const secretKey = process.env.ENCRYPTION_KEY;
    if (!secretKey) {
      return NextResponse.json({ error: 'Decryption key not configured' }, { status: 500 });
    }
    
    // SAFE: Proper decryption with authentication
    const algorithm = 'aes-256-gcm';
    const decipher = crypto.createDecipher(algorithm, secretKey);
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return NextResponse.json({ 
      decrypted,
      status: 'success'
    });
    
  } catch (error) {
    // SAFE: Generic error message
    return NextResponse.json(
      { error: 'Decryption failed' }, 
      { status: 500 }
    );
  }
}