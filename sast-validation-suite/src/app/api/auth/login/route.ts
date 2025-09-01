import { NextRequest, NextResponse } from 'next/server';
import { MongoClient } from 'mongodb';

// A03: INJECTION - Medium Level
// VULNERABLE: NoSQL Injection through MongoDB queries
// SAST should detect: User input flowing into NoSQL query conditions

const mongoUrl = process.env.MONGODB_URL || 'mongodb://localhost:27017';
const dbName = 'calcom_test';

export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json();
    
    if (!username || !password) {
      return NextResponse.json({ error: 'Username and password are required' }, { status: 400 });
    }
    
    const client = new MongoClient(mongoUrl);
    await client.connect();
    const db = client.db(dbName);
    
    // VULNERABLE: NoSQL injection - user input directly in query
    // Attacker could send: {"username": {"$ne": null}, "password": {"$ne": null}}
    const user = await db.collection('users').findOne({
      username: username, // TAINT SOURCE flows to NoSQL query
      password: password  // TAINT SOURCE flows to NoSQL query
    });
    
    await client.close();
    
    if (!user) {
      return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
    }
    
    // Generate and return token (simplified)
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
    return NextResponse.json(
      { error: 'Authentication failed' }, 
      { status: 500 }
    );
  }
}

// VULNERABLE: NoSQL injection in user search
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const filter = searchParams.get('filter');
    const role = searchParams.get('role');
    
    if (!filter) {
      return NextResponse.json({ error: 'Filter parameter is required' }, { status: 400 });
    }
    
    const client = new MongoClient(mongoUrl);
    await client.connect();
    const db = client.db(dbName);
    
    // VULNERABLE: Dynamic NoSQL query construction
    let queryFilter: any = {};
    
    // Parse filter parameter - vulnerable to injection
    try {
      queryFilter = JSON.parse(filter); // VULNERABLE: Direct parsing of user input
    } catch (e) {
      // Fallback to string match
      queryFilter = { username: { $regex: filter, $options: 'i' } };
    }
    
    // Add role filter if provided
    if (role) {
      queryFilter.role = role; // TAINT SOURCE: Could be injected with operators
    }
    
    // SINK: NoSQL query with tainted filter object
    const users = await db.collection('users').find(queryFilter).toArray();
    
    await client.close();
    
    return NextResponse.json(users.map(user => ({
      id: user._id,
      username: user.username,
      role: user.role,
      email: user.email
    })));
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Search failed' }, 
      { status: 500 }
    );
  }
}

// VULNERABLE: NoSQL injection in user update
export async function PUT(request: NextRequest) {
  try {
    const { userId, updateData } = await request.json();
    
    if (!userId || !updateData) {
      return NextResponse.json({ error: 'User ID and update data are required' }, { status: 400 });
    }
    
    const client = new MongoClient(mongoUrl);
    await client.connect();
    const db = client.db(dbName);
    
    // VULNERABLE: Update operation with potential injection
    const result = await db.collection('users').updateOne(
      { _id: userId }, // Could be vulnerable if userId is an object
      { $set: updateData } // VULNERABLE: Direct use of user input in $set operation
    );
    
    await client.close();
    
    if (result.matchedCount === 0) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }
    
    return NextResponse.json({ message: 'User updated successfully' });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Update failed' }, 
      { status: 500 }
    );
  }
}

// Helper function for token generation (simplified)
function generateToken(user: any): string {
  // Simplified token generation for demo
  return Buffer.from(JSON.stringify({
    userId: user._id,
    username: user.username,
    timestamp: Date.now()
  })).toString('base64');
}