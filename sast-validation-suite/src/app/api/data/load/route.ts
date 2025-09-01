import { NextRequest, NextResponse } from 'next/server';

// A08: SOFTWARE AND DATA INTEGRITY FAILURES - Easy Level
// VULNERABLE: Insecure deserialization
// SAST should detect: Dangerous deserialization of user input

export async function POST(request: NextRequest) {
  try {
    const { data, format = 'json' } = await request.json();
    
    if (!data) {
      return NextResponse.json({ error: 'Data is required' }, { status: 400 });
    }
    
    let deserializedData;
    
    switch (format) {
      case 'json':
        // VULNERABLE: JSON.parse without validation
        deserializedData = JSON.parse(data); // Could execute malicious code in some contexts
        break;
        
      case 'base64':
        // VULNERABLE: Base64 decode and parse without validation
        const decoded = Buffer.from(data, 'base64').toString();
        deserializedData = JSON.parse(decoded); // Double vulnerability
        break;
        
      case 'serialized':
        // VULNERABLE: Direct evaluation of serialized data
        deserializedData = eval(`(${data})`); // EXTREMELY DANGEROUS
        break;
        
      default:
        return NextResponse.json({ error: 'Unsupported format' }, { status: 400 });
    }
    
    // Process the deserialized data
    const result = await processUserData(deserializedData);
    
    return NextResponse.json({
      message: 'Data processed successfully',
      format: format,
      result: result
    });
    
  } catch (error: any) {
    return NextResponse.json({
      error: 'Data processing failed',
      message: error.message
    }, { status: 500 });
  }
}

// VULNERABLE: Processing untrusted deserialized data
async function processUserData(data: any): Promise<any> {
  // VULNERABLE: Direct property access without validation
  if (data.type === 'command') {
    // VULNERABLE: Command execution from deserialized data
    const { exec } = require('child_process');
    
    return new Promise((resolve, reject) => {
      exec(data.command, (error: any, stdout: string, stderr: string) => {
        if (error) {
          reject(error);
        } else {
          resolve({ stdout, stderr });
        }
      });
    });
  }
  
  if (data.type === 'function') {
    // VULNERABLE: Function execution from deserialized data
    const func = new Function('data', data.code);
    return func(data.args);
  }
  
  // Return processed data
  return {
    type: data.type,
    value: data.value,
    timestamp: new Date()
  };
}