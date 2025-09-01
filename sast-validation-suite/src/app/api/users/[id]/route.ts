import { NextRequest, NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// A03: INJECTION - Easy Level
// VULNERABLE: SQL Injection through direct concatenation
// SAST should detect: User input directly concatenated into SQL query
export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const userId = params.id; // TAINT SOURCE: user input from URL parameter
    
    // VULNERABLE: Direct SQL concatenation - classic SQL injection
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    
    // SINK: Raw SQL query with tainted input
    const result = await prisma.$queryRawUnsafe(query);
    
    if (!result || (result as any[]).length === 0) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }
    
    return NextResponse.json(result[0]);
    
  } catch (error) {
    // VULNERABLE: Error might expose SQL structure
    return NextResponse.json(
      { error: `Database error: ${error.message}` }, 
      { status: 500 }
    );
  }
}

// VULNERABLE: SQL injection in search functionality
export async function POST(request: NextRequest) {
  try {
    const { searchTerm, orderBy } = await request.json();
    
    if (!searchTerm) {
      return NextResponse.json({ error: 'Search term is required' }, { status: 400 });
    }
    
    // VULNERABLE: Multiple injection points in dynamic query
    const query = `
      SELECT id, name, email, created_at 
      FROM users 
      WHERE name LIKE '%${searchTerm}%' 
      ORDER BY ${orderBy || 'name'}
    `;
    
    // SINK: Complex SQL query with multiple tainted inputs
    const results = await prisma.$queryRawUnsafe(query);
    
    return NextResponse.json(results);
    
  } catch (error) {
    return NextResponse.json(
      { error: `Search failed: ${error.message}` }, 
      { status: 500 }
    );
  }
}

// VULNERABLE: SQL injection in update operation
export async function PUT(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const userId = params.id; // TAINT SOURCE
    const { name, email, status } = await request.json();
    
    // VULNERABLE: Dynamic UPDATE query with concatenation
    let updateQuery = `UPDATE users SET `;
    const updateParts = [];
    
    if (name) {
      updateParts.push(`name = '${name}'`); // VULNERABLE: Direct injection
    }
    
    if (email) {
      updateParts.push(`email = '${email}'`); // VULNERABLE: Direct injection
    }
    
    if (status) {
      updateParts.push(`status = '${status}'`); // VULNERABLE: Direct injection
    }
    
    updateQuery += updateParts.join(', ');
    updateQuery += ` WHERE id = ${userId}`; // VULNERABLE: ID injection
    
    // SINK: Execute vulnerable update query
    await prisma.$executeRawUnsafe(updateQuery);
    
    return NextResponse.json({ message: 'User updated successfully' });
    
  } catch (error) {
    return NextResponse.json(
      { error: `Update failed: ${error.message}` }, 
      { status: 500 }
    );
  }
}