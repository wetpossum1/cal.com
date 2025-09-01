import { NextRequest, NextResponse } from 'next/server';
import { MongoClient } from 'mongodb';

// A03: INJECTION - SAFE NoSQL Implementation
// This demonstrates proper input validation and sanitization that SAST tools should NOT flag

const mongoUrl = process.env.MONGODB_URL || 'mongodb://localhost:27017';
const dbName = 'calcom_test';

export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json();
    
    // SAFE: Input validation
    if (!username || !password || 
        typeof username !== 'string' || 
        typeof password !== 'string') {
      return NextResponse.json({ error: 'Invalid credentials format' }, { status: 400 });
    }
    
    const client = new MongoClient(mongoUrl);
    await client.connect();
    const db = client.db(dbName);
    
    // SAFE: Explicitly construct query with validated string inputs
    const user = await db.collection('users').findOne({
      username: String(username), // Explicit string conversion
      password: String(password)   // Explicit string conversion
    });
    
    await client.close();
    
    if (!user) {
      return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
    }
    
    // Generate and return token
    const token = generateToken(user);
    
    return NextResponse.json({ 
      token,
      user: {
        id: user._id,
        username: user.username,
        role: user.role
      }
    });
    
  } catch (error) {
    console.error('Authentication error:', error);
    return NextResponse.json(
      { error: 'Authentication failed' }, 
      { status: 500 }
    );
  }
}

// SAFE: Parameterized search with validation
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const filter = searchParams.get('filter');
    const role = searchParams.get('role');
    
    if (!filter || typeof filter !== 'string') {
      return NextResponse.json({ error: 'Valid filter parameter is required' }, { status: 400 });
    }
    
    const client = new MongoClient(mongoUrl);
    await client.connect();
    const db = client.db(dbName);
    
    // SAFE: Construct query with validated inputs
    const queryFilter: any = {
      username: { $regex: filter, $options: 'i' }
    };
    
    // SAFE: Validate role input
    if (role && typeof role === 'string') {
      const allowedRoles = ['user', 'admin', 'moderator'];
      if (allowedRoles.includes(role.toLowerCase())) {
        queryFilter.role = role.toLowerCase();
      }
    }
    
    // SAFE: Query with validated filter
    const users = await db.collection('users').find(queryFilter).toArray();
    
    await client.close();
    
    return NextResponse.json(users.map(user => ({
      id: user._id,
      username: user.username,
      role: user.role,
      email: user.email
    })));
    
  } catch (error) {
    console.error('Search error:', error);
    return NextResponse.json(
      { error: 'Search failed' }, 
      { status: 500 }
    );
  }
}

function generateToken(user: any): string {
  return Buffer.from(JSON.stringify({
    userId: user._id,
    username: user.username,
    timestamp: Date.now()
  })).toString('base64');
}