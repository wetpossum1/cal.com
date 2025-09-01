import { NextRequest, NextResponse } from 'next/server';
import { getUserById } from '@/services/userService';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '@/app/api/auth/[...nextauth]/route';

// A01: BROKEN ACCESS CONTROL - SAFE Implementation
// This demonstrates proper authorization controls that SAST tools should NOT flag
export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    // SAFE: Get authenticated session
    const session = await getServerSession(authOptions);
    
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    // SAFE: Check if user has admin role
    if (session.user.role !== 'ADMIN') {
      return NextResponse.json({ error: 'Forbidden - Admin access required' }, { status: 403 });
    }
    
    const userId = params.id;
    
    // SAFE: Now safe to query user data with proper authorization
    const user = await getUserById(userId);
    
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }
    
    // Return filtered data based on permissions
    return NextResponse.json({
      id: user.id,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
      isActive: user.isActive
    });
    
  } catch (error) {
    console.error('Error fetching user:', error);
    return NextResponse.json(
      { error: 'Internal server error' }, 
      { status: 500 }
    );
  }
}

// SAFE: Proper authorization for user updates
export async function PUT(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession(authOptions);
    
    if (!session?.user || session.user.role !== 'ADMIN') {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 403 });
    }
    
    const userId = params.id;
    const body = await request.json();
    
    // Additional validation
    if (!['USER', 'ADMIN', 'MODERATOR'].includes(body.role)) {
      return NextResponse.json({ error: 'Invalid role' }, { status: 400 });
    }
    
    const updatedUser = await updateUserRole(userId, body.role);
    
    return NextResponse.json(updatedUser);
  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to update user' }, 
      { status: 500 }
    );
  }
}

// Import placeholder functions
async function updateUserRole(userId: string, role: string) {
  return { id: userId, role };
}