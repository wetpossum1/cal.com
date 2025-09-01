import { NextRequest, NextResponse } from 'next/server';

// A05: SECURITY MISCONFIGURATION - Easy Level
// VULNERABLE: Debug mode enabled in production
// SAST should detect: Debug functionality exposed, verbose error messages

export async function GET(request: NextRequest) {
  try {
    // VULNERABLE: Debug mode check that's always true
    const debugMode = process.env.NODE_ENV !== 'production' || true; // Always true!
    
    if (debugMode) {
      // VULNERABLE: Exposing sensitive system information
      const systemInfo = {
        nodeVersion: process.version,
        platform: process.platform,
        architecture: process.arch,
        memoryUsage: process.memoryUsage(),
        uptime: process.uptime(),
        // VULNERABLE: Exposing environment variables
        environment: process.env,
        // VULNERABLE: Exposing internal paths
        cwd: process.cwd(),
        execPath: process.execPath
      };
      
      return NextResponse.json({
        debug: true,
        message: 'Debug mode is enabled',
        systemInfo,
        // VULNERABLE: Stack trace exposure
        stackTrace: new Error().stack
      });
    }
    
    return NextResponse.json({ debug: false });
    
  } catch (error: any) {
    // VULNERABLE: Detailed error information exposure
    return NextResponse.json({
      error: 'Debug endpoint failed',
      message: error.message,
      stack: error.stack,
      name: error.name,
      // VULNERABLE: Full error object exposure
      fullError: error
    }, { status: 500 });
  }
}

// VULNERABLE: Development endpoints left in production
export async function POST(request: NextRequest) {
  try {
    const { command } = await request.json();
    
    // VULNERABLE: Command execution in debug mode
    if (process.env.DEBUG === 'true') {
      const { exec } = require('child_process');
      
      return new Promise((resolve) => {
        // VULNERABLE: Command injection through debug functionality
        exec(command, (error: any, stdout: string, stderr: string) => {
          resolve(NextResponse.json({
            command,
            stdout,
            stderr,
            error: error?.message
          }));
        });
      });
    }
    
    return NextResponse.json({ error: 'Debug mode not enabled' });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Command execution failed' },
      { status: 500 }
    );
  }
}