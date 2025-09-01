// A01: BROKEN ACCESS CONTROL - Medium Level Service Layer
// VULNERABLE: Service layer missing authorization checks
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export class ProfileService {
  
  // VULNERABLE: No ownership verification in service layer
  async getProfile(id: string) { // Receives tainted ID from controller
    try {
      // SINK: Database query without ownership verification
      const profile = await prisma.profile.findUnique({
        where: { id },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true
            }
          },
          // Includes sensitive data that should be access-controlled
          privateSettings: true,
          paymentInfo: true
        }
      });
      
      return profile;
    } catch (error) {
      throw new Error('Database query failed');
    }
  }
  
  // VULNERABLE: Update without ownership check
  async updateProfile(id: string, data: any) {
    try {
      // SINK: Updates any profile without verifying ownership
      const updatedProfile = await prisma.profile.update({
        where: { id },
        data: {
          name: data.name,
          bio: data.bio,
          avatar: data.avatar,
          // Could modify sensitive fields
          isPublic: data.isPublic,
          settings: data.settings
        }
      });
      
      return updatedProfile;
    } catch (error) {
      throw new Error('Profile update failed');
    }
  }
  
  // VULNERABLE: Delete without ownership verification
  async deleteProfile(id: string) {
    try {
      // Complex deletion flow that obscures the authorization issue
      const profile = await this.getProfile(id);
      
      if (!profile) {
        return false;
      }
      
      // Delete associated data first
      await this.cleanupProfileData(profile);
      
      // SINK: Delete profile without ownership check
      await prisma.profile.delete({
        where: { id }
      });
      
      return true;
    } catch (error) {
      throw new Error('Profile deletion failed');
    }
  }
  
  // Helper method that adds complexity to taint tracking
  private async cleanupProfileData(profile: any) {
    // Delete related records
    await prisma.profileSettings.deleteMany({
      where: { profileId: profile.id }
    });
    
    await prisma.profileImage.deleteMany({
      where: { profileId: profile.id }
    });
  }
  
  // SAFE: Proper implementation with ownership check
  async getProfileSafe(id: string, userId: string) {
    try {
      const profile = await prisma.profile.findFirst({
        where: { 
          id,
          userId // SAFE: Verify ownership
        },
        include: {
          user: {
            select: {
              id: true,
              name: true
            }
          }
        }
      });
      
      return profile;
    } catch (error) {
      throw new Error('Database query failed');
    }
  }
  
  // SAFE: Update with proper authorization
  async updateProfileSafe(id: string, userId: string, data: any) {
    try {
      // First verify ownership
      const existingProfile = await prisma.profile.findFirst({
        where: { id, userId }
      });
      
      if (!existingProfile) {
        throw new Error('Profile not found or access denied');
      }
      
      const updatedProfile = await prisma.profile.update({
        where: { id },
        data: {
          name: data.name,
          bio: data.bio,
          avatar: data.avatar
        }
      });
      
      return updatedProfile;
    } catch (error) {
      throw new Error('Profile update failed');
    }
  }
}