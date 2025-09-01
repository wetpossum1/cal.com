import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';

// A02: CRYPTOGRAPHIC FAILURES - Easy Level
// VULNERABLE: Hardcoded secrets and weak encryption
// SAST should detect: Hardcoded cryptographic keys and weak algorithms

// VULNERABLE: Hardcoded secret key
const SECRET_KEY = 'hardcoded-secret-key-123'; // SAST should flag this
const BACKUP_KEY = 'backup-key-456'; // Multiple hardcoded keys

export async function POST(request: NextRequest) {
  try {
    const { data } = await request.json();
    
    if (!data) {
      return NextResponse.json({ error: 'Data is required' }, { status: 400 });
    }
    
    // VULNERABLE: Using deprecated createCipher (weak encryption)
    const cipher = crypto.createCipher('aes192', SECRET_KEY);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return NextResponse.json({ 
      encrypted,
      algorithm: 'aes192',
      keySource: 'hardcoded'
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Encryption failed' }, 
      { status: 500 }
    );
  }
}

// VULNERABLE: Decryption with hardcoded key
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const encryptedData = searchParams.get('data');
    
    if (!encryptedData) {
      return NextResponse.json({ error: 'Encrypted data is required' }, { status: 400 });
    }
    
    // VULNERABLE: Using deprecated createDecipher
    const decipher = crypto.createDecipher('aes192', SECRET_KEY);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return NextResponse.json({ 
      decrypted,
      keyUsed: SECRET_KEY.substring(0, 5) + '...' // Partial key exposure
    });
    
  } catch (error) {
    // VULNERABLE: Error reveals key information
    return NextResponse.json(
      { 
        error: 'Decryption failed',
        hint: `Try using key starting with ${SECRET_KEY.substring(0, 3)}`
      }, 
      { status: 500 }
    );
  }
}

// VULNERABLE: Key rotation with hardcoded keys
export async function PUT(request: NextRequest) {
  try {
    const { data, useBackup } = await request.json();
    
    // VULNERABLE: Key selection based on user input but still hardcoded
    const keyToUse = useBackup ? BACKUP_KEY : SECRET_KEY;
    
    const cipher = crypto.createCipher('des', keyToUse); // VULNERABLE: Weak DES algorithm
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return NextResponse.json({ 
      encrypted,
      algorithm: 'des',
      keyId: useBackup ? 'backup' : 'primary'
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Encryption with rotation failed' }, 
      { status: 500 }
    );
  }
}