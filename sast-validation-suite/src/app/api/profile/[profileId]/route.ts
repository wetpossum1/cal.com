import { NextRequest, NextResponse } from 'next/server';
import { ProfileService } from '@/services/profileService';

// A01: BROKEN ACCESS CONTROL - Medium Level
// VULNERABLE: Indirect Object Reference (IDOR) through service layer
// SAST should detect: User input flowing to service without proper ownership verification
export async function GET(
  request: NextRequest,
  { params }: { params: { profileId: string } }
) {
  try {
    const profileId = params.profileId; // TAINT SOURCE: user input from URL
    
    // Taint flows to service layer without user context for authorization
    const profileService = new ProfileService();
    const profile = await profileService.getProfile(profileId);
    
    if (!profile) {
      return NextResponse.json({ error: 'Profile not found' }, { status: 404 });
    }
    
    // VULNERABLE: Returns any user's profile without ownership check
    return NextResponse.json(profile);
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to fetch profile' }, 
      { status: 500 }
    );
  }
}

// VULNERABLE: Profile update without ownership verification
export async function PUT(
  request: NextRequest,
  { params }: { params: { profileId: string } }
) {
  try {
    const profileId = params.profileId; // TAINT SOURCE
    const updateData = await request.json();
    
    // Validate some fields but miss the authorization check
    if (!updateData.name || updateData.name.length < 2) {
      return NextResponse.json({ error: 'Name is required' }, { status: 400 });
    }
    
    const profileService = new ProfileService();
    // VULNERABLE: Updates any profile without checking ownership
    const updatedProfile = await profileService.updateProfile(profileId, updateData);
    
    return NextResponse.json(updatedProfile);
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to update profile' }, 
      { status: 500 }
    );
  }
}

// VULNERABLE: Profile deletion through indirect flow
export async function DELETE(
  request: NextRequest,
  { params }: { params: { profileId: string } }
) {
  try {
    const profileId = params.profileId; // TAINT SOURCE
    
    // Some validation that looks like security but isn't
    if (!profileId || profileId.length < 3) {
      return NextResponse.json({ error: 'Invalid profile ID' }, { status: 400 });
    }
    
    const profileService = new ProfileService();
    
    // VULNERABLE: Profile deletion flows through service without ownership check
    const result = await profileService.deleteProfile(profileId);
    
    if (!result) {
      return NextResponse.json({ error: 'Profile not found' }, { status: 404 });
    }
    
    return NextResponse.json({ message: 'Profile deleted successfully' });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to delete profile' }, 
      { status: 500 }
    );
  }
}