// User Service - Supporting service for Access Control test cases
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export interface User {
  id: string;
  email: string;
  name: string;
  role: 'USER' | 'ADMIN' | 'MODERATOR';
  createdAt: Date;
  lastLogin?: Date;
  isActive: boolean;
  permissions: string[];
  internalNotes?: string;
}

export class UserService {
  
  async getUserById(id: string): Promise<User | null> {
    try {
      const user = await prisma.user.findUnique({
        where: { id },
        include: {
          permissions: true
        }
      });
      
      if (!user) {
        return null;
      }
      
      return {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role as 'USER' | 'ADMIN' | 'MODERATOR',
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
        isActive: user.isActive,
        permissions: user.permissions.map(p => p.name),
        internalNotes: user.internalNotes
      };
      
    } catch (error) {
      throw new Error('Failed to fetch user');
    }
  }
  
  async updateUserRole(id: string, role: string): Promise<User> {
    try {
      const updatedUser = await prisma.user.update({
        where: { id },
        data: { role },
        include: {
          permissions: true
        }
      });
      
      return {
        id: updatedUser.id,
        email: updatedUser.email,
        name: updatedUser.name,
        role: updatedUser.role as 'USER' | 'ADMIN' | 'MODERATOR',
        createdAt: updatedUser.createdAt,
        lastLogin: updatedUser.lastLogin,
        isActive: updatedUser.isActive,
        permissions: updatedUser.permissions.map(p => p.name)
      };
      
    } catch (error) {
      throw new Error('Failed to update user role');
    }
  }
  
  async deleteUser(id: string): Promise<boolean> {
    try {
      await prisma.user.delete({
        where: { id }
      });
      
      return true;
    } catch (error) {
      throw new Error('Failed to delete user');
    }
  }
}

// Export standalone functions for backward compatibility
export const getUserById = async (id: string): Promise<User | null> => {
  const userService = new UserService();
  return userService.getUserById(id);
};

export const updateUserRole = async (id: string, role: string): Promise<User> => {
  const userService = new UserService();
  return userService.updateUserRole(id, role);
};

export const deleteUser = async (id: string): Promise<boolean> => {
  const userService = new UserService();
  return userService.deleteUser(id);
};