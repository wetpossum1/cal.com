import { NextRequest, NextResponse } from 'next/server';
import { getUserById } from '@/services/userService';

// A01: BROKEN ACCESS CONTROL - Easy Level
// VULNERABLE: Direct authorization bypass - no access control check
// SAST should detect: Missing authorization middleware/check before sensitive operation
export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const userId = params.id; // TAINT SOURCE: user input from URL parameter
    
    // VULNERABLE: No authorization check - anyone can access any user's admin data
    // SINK: Database query with user ID, no auth verification
    const user = await getUserById(userId);
    
    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }
    
    // Returns sensitive admin data without permission check
    return NextResponse.json({
      id: user.id,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin,
      // Sensitive admin-only fields
      isActive: user.isActive,
      permissions: user.permissions,
      internalNotes: user.internalNotes
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Internal server error' }, 
      { status: 500 }
    );
  }
}

// VULNERABLE: Admin user modification without authorization
export async function PUT(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const userId = params.id; // TAINT SOURCE
    const body = await request.json();
    
    // VULNERABLE: No check if requester is admin or owns the account
    const updatedUser = await updateUserRole(userId, body.role);
    
    return NextResponse.json(updatedUser);
  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to update user' }, 
      { status: 500 }
    );
  }
}

// VULNERABLE: User deletion without proper authorization
export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const userId = params.id; // TAINT SOURCE
    
    // VULNERABLE: Anyone can delete any user
    await deleteUser(userId);
    
    return NextResponse.json({ message: 'User deleted successfully' });
  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to delete user' }, 
      { status: 500 }
    );
  }
}

// Import placeholder functions
async function updateUserRole(userId: string, role: string) {
  // This would update user role in database
  return { id: userId, role };
}

async function deleteUser(userId: string) {
  // This would delete user from database
  return true;
}