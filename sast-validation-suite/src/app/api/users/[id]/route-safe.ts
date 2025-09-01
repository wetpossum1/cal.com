import { NextRequest, NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// A03: INJECTION - SAFE Implementation
// This demonstrates proper parameterization that SAST tools should NOT flag
export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const userId = params.id;
    
    // Input validation
    if (!userId || isNaN(Number(userId))) {
      return NextResponse.json({ error: 'Invalid user ID' }, { status: 400 });
    }
    
    // SAFE: Using parameterized query
    const user = await prisma.user.findUnique({
      where: { id: parseInt(userId) },
      select: {
        id: true,
        name: true,
        email: true,
        createdAt: true
      }
    });
    
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }
    
    return NextResponse.json(user);
    
  } catch (error) {
    // SAFE: Generic error message
    console.error('Database query error:', error);
    return NextResponse.json(
      { error: 'Internal server error' }, 
      { status: 500 }
    );
  }
}

// SAFE: Parameterized search query
export async function POST(request: NextRequest) {
  try {
    const { searchTerm, orderBy } = await request.json();
    
    if (!searchTerm || typeof searchTerm !== 'string') {
      return NextResponse.json({ error: 'Valid search term is required' }, { status: 400 });
    }
    
    // Input validation for orderBy
    const allowedOrderFields = ['name', 'email', 'createdAt'];
    const safeOrderBy = allowedOrderFields.includes(orderBy) ? orderBy : 'name';
    
    // SAFE: Using Prisma's query builder
    const results = await prisma.user.findMany({
      where: {
        name: {
          contains: searchTerm
        }
      },
      orderBy: {
        [safeOrderBy]: 'asc'
      },
      select: {
        id: true,
        name: true,
        email: true,
        createdAt: true
      }
    });
    
    return NextResponse.json(results);
    
  } catch (error) {
    console.error('Search error:', error);
    return NextResponse.json(
      { error: 'Search failed' }, 
      { status: 500 }
    );
  }
}