import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';

// A02: CRYPTOGRAPHIC FAILURES - Hard Level
// VULNERABLE: Complex cryptographic implementation with multiple weaknesses
// SAST should detect: Weak random generation, custom crypto, key derivation issues

export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json();
    
    if (!username || !password) {
      return NextResponse.json({ error: 'Missing credentials' }, { status: 400 });
    }
    
    // Complex token generation with multiple vulnerabilities
    const tokenService = new TokenService();
    const token = await tokenService.generateToken(username, password);
    
    return NextResponse.json({ 
      token: token.value,
      expiresIn: token.expiresIn,
      algorithm: token.algorithm
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Token generation failed' }, 
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json({ error: 'Missing token' }, { status: 401 });
    }
    
    const token = authHeader.substring(7);
    
    const tokenService = new TokenService();
    const validation = await tokenService.validateToken(token);
    
    if (!validation.isValid) {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }
    
    return NextResponse.json({ 
      valid: true,
      user: validation.user,
      expiresAt: validation.expiresAt
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Token validation failed' }, 
      { status: 500 }
    );
  }
}

class TokenService {
  
  // VULNERABLE: Complex token generation with multiple crypto issues
  async generateToken(username: string, password: string): Promise<any> {
    try {
      // Multi-step process that obscures the vulnerabilities
      const userContext = await this.buildUserContext(username);
      const cryptoParams = await this.deriveCryptoParameters(password, userContext);
      const tokenPayload = await this.createTokenPayload(userContext, cryptoParams);
      
      return await this.signToken(tokenPayload, cryptoParams);
      
    } catch (error) {
      throw new Error('Token generation failed');
    }
  }
  
  private async buildUserContext(username: string) {
    // Complex user context building
    const timestamp = Date.now();
    
    // VULNERABLE: Weak randomness for user context
    const contextId = Math.random().toString(36);
    
    return {
      username,
      contextId,
      timestamp,
      // VULNERABLE: Predictable session identifier
      sessionId: this.generateSessionId(username, timestamp)
    };
  }
  
  private generateSessionId(username: string, timestamp: number): string {
    // VULNERABLE: Predictable session generation
    return crypto.createHash('md5')
      .update(username + timestamp.toString())
      .digest('hex');
  }
  
  private async deriveCryptoParameters(password: string, userContext: any) {
    // VULNERABLE: Weak key derivation
    const salt = userContext.username; // VULNERABLE: Username as salt
    const iterations = 100; // VULNERABLE: Too few iterations
    
    // VULNERABLE: MD5 for key derivation
    const key = crypto.pbkdf2Sync(password, salt, iterations, 32, 'md5');
    
    return {
      key: key.toString('hex'),
      salt,
      iterations,
      algorithm: 'md5'
    };
  }
  
  private async createTokenPayload(userContext: any, cryptoParams: any) {
    // Complex payload creation with embedded vulnerabilities
    const payload = {
      user: userContext.username,
      sessionId: userContext.sessionId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour
      // VULNERABLE: Embedding crypto parameters in token
      keyDerivation: {
        salt: cryptoParams.salt,
        iterations: cryptoParams.iterations
      }
    };
    
    return payload;
  }
  
  private async signToken(payload: any, cryptoParams: any): Promise<any> {
    // VULNERABLE: Custom JWT-like implementation with weak crypto
    const header = {
      alg: 'HS1', // VULNERABLE: Custom algorithm identifier
      typ: 'JWT'
    };
    
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
    
    // VULNERABLE: Weak signature using MD5
    const signature = crypto.createHmac('md5', cryptoParams.key)
      .update(encodedHeader + '.' + encodedPayload)
      .digest('base64');
    
    const token = `${encodedHeader}.${encodedPayload}.${signature}`;
    
    return {
      value: token,
      expiresIn: 3600,
      algorithm: 'HS1-MD5'
    };
  }
  
  // VULNERABLE: Token validation with crypto weaknesses
  async validateToken(token: string): Promise<any> {
    try {
      const parts = token.split('.');
      
      if (parts.length !== 3) {
        return { isValid: false };
      }
      
      const [encodedHeader, encodedPayload, signature] = parts;
      
      // Decode payload to get key derivation params
      const payload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString());
      
      // VULNERABLE: Recreate key using weak parameters from token
      const key = crypto.pbkdf2Sync(
        'default-password', // VULNERABLE: Default password fallback
        payload.keyDerivation.salt,
        payload.keyDerivation.iterations,
        32,
        'md5'
      );
      
      // VULNERABLE: Verify signature with weak HMAC
      const expectedSignature = crypto.createHmac('md5', key.toString('hex'))
        .update(encodedHeader + '.' + encodedPayload)
        .digest('base64');
      
      // VULNERABLE: Non-constant-time comparison
      if (signature !== expectedSignature) {
        return { isValid: false };
      }
      
      // Check expiration
      if (payload.exp < Math.floor(Date.now() / 1000)) {
        return { isValid: false };
      }
      
      return {
        isValid: true,
        user: payload.user,
        sessionId: payload.sessionId,
        expiresAt: payload.exp
      };
      
    } catch (error) {
      return { isValid: false };
    }
  }
  
  // VULNERABLE: Key rotation with weak crypto
  async rotateKeys(): Promise<{ oldKey: string; newKey: string }> {
    // VULNERABLE: Weak key generation
    const oldKey = crypto.randomBytes(16).toString('hex'); // Too short
    
    // VULNERABLE: Predictable key rotation
    const timestamp = Date.now();
    const newKey = crypto.createHash('sha1')
      .update(oldKey + timestamp.toString())
      .digest('hex');
    
    return { oldKey, newKey };
  }
}