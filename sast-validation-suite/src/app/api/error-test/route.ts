import { NextRequest, NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// A05: SECURITY MISCONFIGURATION - Medium Level
// VULNERABLE: Verbose error messages exposing internal details
// SAST should detect: Database structure exposure, stack trace leakage

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const userId = searchParams.get('userId');
    
    if (!userId) {
      return NextResponse.json({ error: 'User ID is required' }, { status: 400 });
    }
    
    // VULNERABLE: Raw query that will expose database schema on error
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    const result = await prisma.$queryRawUnsafe(query);
    
    return NextResponse.json(result);
    
  } catch (error: any) {
    // VULNERABLE: Detailed database error exposure
    return NextResponse.json({
      error: 'Database query failed',
      // VULNERABLE: Exposes database structure
      sqlError: error.message,
      code: error.code,
      // VULNERABLE: Stack trace exposure
      stack: error.stack,
      // VULNERABLE: Database connection details
      meta: error.meta,
      // VULNERABLE: Query details
      query: error.query
    }, { status: 500 });
  }
}

// VULNERABLE: Exception handler that reveals internal paths
export async function POST(request: NextRequest) {
  try {
    const data = await request.json();
    
    // Force an error to demonstrate verbose error handling
    throw new Error(`Processing failed for data: ${JSON.stringify(data)}`);
    
  } catch (error: any) {
    // VULNERABLE: Global exception handler with too much detail
    const errorResponse = {
      timestamp: new Date().toISOString(),
      error: {
        name: error.name,
        message: error.message,
        // VULNERABLE: Full stack trace with file paths
        stack: error.stack,
        // VULNERABLE: Source file information
        fileName: error.fileName,
        lineNumber: error.lineNumber,
        columnNumber: error.columnNumber
      },
      // VULNERABLE: Request details in error
      request: {
        method: request.method,
        url: request.url,
        headers: Object.fromEntries(request.headers.entries())
      },
      // VULNERABLE: Process information
      process: {
        cwd: process.cwd(),
        platform: process.platform,
        version: process.version
      }
    };
    
    return NextResponse.json(errorResponse, { 
      status: 500,
      // VULNERABLE: Detailed error headers
      headers: {
        'X-Error-Type': error.constructor.name,
        'X-Error-Code': error.code || 'UNKNOWN',
        'X-Debug-Info': 'Check logs for more details'
      }
    });
  }
}