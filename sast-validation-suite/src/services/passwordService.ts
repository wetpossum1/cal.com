// A02: CRYPTOGRAPHIC FAILURES - Medium Level
// VULNERABLE: Weak hashing algorithms for password storage
// SAST should detect: Use of MD5/SHA1 for password hashing
import crypto from 'crypto';
import md5 from 'md5';

export class PasswordService {
  
  // VULNERABLE: Using MD5 for password hashing
  hashPassword(password: string): string {
    // SAST should flag this - MD5 is cryptographically broken
    return md5(password);
  }
  
  // VULNERABLE: Using SHA1 for password hashing  
  hashPasswordSHA1(password: string): string {
    // SAST should flag this - SHA1 is weak for password hashing
    return crypto.createHash('sha1').update(password).digest('hex');
  }
  
  // VULNERABLE: Using SHA256 without salt for passwords
  hashPasswordSHA256(password: string): string {
    // SAST should flag this - no salt makes it vulnerable to rainbow tables
    return crypto.createHash('sha256').update(password).digest('hex');
  }
  
  // Called from controller - flows through multiple methods
  async verifyPassword(inputPassword: string, storedHash: string): Promise<boolean> {
    try {
      // The vulnerability flows through the hash function call
      const hashedInput = this.hashPassword(inputPassword);
      
      // Constant-time comparison (good practice but doesn't fix the weak hashing)
      return crypto.timingSafeEqual(
        Buffer.from(hashedInput),
        Buffer.from(storedHash)
      );
      
    } catch (error) {
      return false;
    }
  }
  
  // VULNERABLE: Password strength validation that suggests weak practices
  validatePasswordStrength(password: string): { isValid: boolean; issues: string[] } {
    const issues: string[] = [];
    
    if (password.length < 6) { // VULNERABLE: Too short minimum length
      issues.push('Password must be at least 6 characters'); // Should be 12+
    }
    
    if (!/\d/.test(password)) {
      issues.push('Password must contain at least one number');
    }
    
    // Missing checks for uppercase, special characters, etc.
    
    return {
      isValid: issues.length === 0,
      issues
    };
  }
  
  // VULNERABLE: Password recovery with weak token generation
  generateResetToken(): string {
    // SAST should flag this - Math.random() is not cryptographically secure
    const token = Math.random().toString(36).substring(2, 15) +
                 Math.random().toString(36).substring(2, 15);
    
    return token;
  }
  
  // VULNERABLE: Token verification with timing attack possibility
  verifyResetToken(providedToken: string, storedToken: string): boolean {
    // VULNERABLE: String comparison allows timing attacks
    return providedToken === storedToken;
  }
  
  // VULNERABLE: Session ID generation with weak randomness
  generateSessionId(): string {
    // Multiple weak random sources
    const timestamp = Date.now().toString();
    const randomPart = Math.random().toString(36);
    
    // VULNERABLE: Predictable session ID
    return md5(timestamp + randomPart);
  }
  
  // Helper method that adds complexity to the vulnerable flow
  private preprocessPassword(password: string): string {
    // Some basic preprocessing that doesn't fix the core issue
    return password.trim().toLowerCase();
  }
  
  // VULNERABLE: Multi-step password processing with weak crypto
  async processUserPassword(rawPassword: string): Promise<string> {
    // Complex flow that obscures the vulnerability
    const cleaned = this.preprocessPassword(rawPassword);
    const validated = this.validatePasswordForProcessing(cleaned);
    
    if (!validated.isValid) {
      throw new Error('Invalid password format');
    }
    
    // Still uses weak hashing despite complex processing
    return this.hashPassword(validated.password);
  }
  
  private validatePasswordForProcessing(password: string): { isValid: boolean; password: string } {
    // Complex validation that looks secure
    if (password.length === 0) {
      return { isValid: false, password };
    }
    
    // Remove potential injection characters
    const cleaned = password.replace(/[<>]/g, '');
    
    return { isValid: true, password: cleaned };
  }
}

// SAFE implementations for comparison
export class SecurePasswordService {
  
  // SAFE: Using bcrypt for password hashing
  async hashPassword(password: string): Promise<string> {
    const bcrypt = require('bcryptjs');
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
  }
  
  // SAFE: Secure password verification
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    const bcrypt = require('bcryptjs');
    return await bcrypt.compare(password, hash);
  }
  
  // SAFE: Cryptographically secure token generation
  generateResetToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }
  
  // SAFE: Constant-time token verification
  verifyResetToken(providedToken: string, storedToken: string): boolean {
    try {
      return crypto.timingSafeEqual(
        Buffer.from(providedToken, 'hex'),
        Buffer.from(storedToken, 'hex')
      );
    } catch (error) {
      return false;
    }
  }
}