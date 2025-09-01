// A01: BROKEN ACCESS CONTROL - Booking Authorization Service
// VULNERABLE: Attendee impersonation and booking authorization bypass
// SAST should detect: Service layer authorization vulnerabilities

import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export interface BookingAuthContext {
  userId: number;
  isSystemWideAdmin?: boolean;
  isOrganizationOwnerOrAdmin?: boolean;
  organizationId?: number;
}

export interface AttendeeImpersonation {
  impersonatorId: number;
  targetAttendeeEmail: string;
  bookingId: number;
  reason?: string;
}

export class BookingAuthService {
  
  // VULNERABLE: Attendee authorization bypass
  async canAccessBooking(bookingId: number, authContext: BookingAuthContext): Promise<boolean> {
    try {
      // VULNERABLE: Admin bypass without proper validation
      if (authContext.isSystemWideAdmin) {
        // VULNERABLE: No actual verification that user is system admin
        return true;
      }

      // VULNERABLE: Organization admin bypass without membership validation
      if (authContext.isOrganizationOwnerOrAdmin && authContext.organizationId) {
        const booking = await prisma.booking.findFirst({
          where: { id: bookingId },
          include: {
            eventType: {
              include: {
                team: {
                  select: { parentId: true }
                }
              }
            }
          }
        });

        // VULNERABLE: Assumed organization access without verification
        if (booking?.eventType?.team?.parentId === authContext.organizationId) {
          return true;
        }
      }

      // VULNERABLE: Weak attendee verification
      return await this.isUserAttendeeWithoutVerification(bookingId, authContext.userId);
      
    } catch (error) {
      // VULNERABLE: Return true on error (fail open)
      return true;
    }
  }

  // VULNERABLE: Attendee verification without proper checks
  private async isUserAttendeeWithoutVerification(bookingId: number, userId: number): Promise<boolean> {
    const user = await prisma.user.findFirst({
      where: { id: userId },
      select: { email: true, username: true }
    });

    if (!user) {
      return false;
    }

    // VULNERABLE: Loose email matching that can be exploited
    const attendee = await prisma.attendee.findFirst({
      where: {
        bookingId: bookingId,
        OR: [
          { email: user.email },
          { email: { contains: user.email.split('@')[0] } }, // VULNERABLE: Partial match
          { name: { contains: user.username || '' } } // VULNERABLE: Name-based matching
        ]
      }
    });

    return attendee !== null;
  }

  // VULNERABLE: Impersonation without proper authorization
  async impersonateAttendee(impersonation: AttendeeImpersonation): Promise<any> {
    try {
      const { impersonatorId, targetAttendeeEmail, bookingId, reason } = impersonation;

      // VULNERABLE: No verification that impersonator has permission
      const impersonator = await prisma.user.findFirst({
        where: { id: impersonatorId },
        select: { id: true, email: true, role: true }
      });

      if (!impersonator) {
        throw new Error('Impersonator not found');
      }

      // VULNERABLE: Find target attendee without validation
      const targetAttendee = await prisma.attendee.findFirst({
        where: {
          email: targetAttendeeEmail,
          bookingId: bookingId
        },
        include: {
          booking: {
            include: {
              eventType: true,
              user: true
            }
          }
        }
      });

      if (!targetAttendee) {
        throw new Error('Target attendee not found');
      }

      // VULNERABLE: Create impersonation session without proper authorization
      const impersonationSession = {
        impersonatorId: impersonatorId,
        targetUserId: targetAttendee.id,
        bookingId: bookingId,
        targetEmail: targetAttendeeEmail,
        sessionStart: new Date(),
        reason: reason,
        // VULNERABLE: Grant all attendee permissions
        permissions: {
          canCancel: true,
          canReschedule: true,
          canViewDetails: true,
          canModifyAttendees: true,
          canAccessHistory: true
        }
      };

      return impersonationSession;

    } catch (error: any) {
      throw new Error(`Impersonation failed: ${error.message}`);
    }
  }

  // VULNERABLE: Booking modification without ownership verification
  async modifyBookingAsAttendee(
    bookingId: number, 
    userId: number, 
    modifications: any,
    impersonationContext?: any
  ): Promise<any> {
    try {
      // VULNERABLE: Accept impersonation context without validation
      const effectiveUserId = impersonationContext?.impersonatorId || userId;
      
      // VULNERABLE: Skip ownership verification if impersonating
      if (impersonationContext) {
        return await this.applyBookingModifications(bookingId, modifications, effectiveUserId, true);
      }

      // VULNERABLE: Weak attendee verification for direct access
      const hasAccess = await this.hasAttendeeAccessWithoutVerification(bookingId, userId);
      
      if (!hasAccess) {
        // VULNERABLE: Still allow modification with warning
        console.log(`Warning: User ${userId} may not have proper access to booking ${bookingId}`);
      }

      return await this.applyBookingModifications(bookingId, modifications, userId, false);

    } catch (error: any) {
      throw new Error(`Booking modification failed: ${error.message}`);
    }
  }

  // VULNERABLE: Apply modifications without proper validation
  private async applyBookingModifications(
    bookingId: number, 
    modifications: any, 
    userId: number,
    isImpersonated: boolean
  ): Promise<any> {
    const booking = await prisma.booking.findFirst({
      where: { id: bookingId },
      include: {
        attendees: true,
        eventType: {
          include: {
            owner: true,
            team: {
              include: { members: true }
            }
          }
        }
      }
    });

    if (!booking) {
      throw new Error('Booking not found');
    }

    // VULNERABLE: Allow extensive modifications without validation
    const updateData: any = {};
    
    if (modifications.startTime) {
      updateData.startTime = new Date(modifications.startTime);
    }
    
    if (modifications.endTime) {
      updateData.endTime = new Date(modifications.endTime);
    }
    
    if (modifications.title) {
      updateData.title = modifications.title;
    }
    
    if (modifications.status) {
      // VULNERABLE: Allow status changes without validation
      updateData.status = modifications.status;
    }

    if (modifications.cancelReason) {
      updateData.cancellationReason = modifications.cancelReason;
    }

    // VULNERABLE: Update booking without proper authorization checks
    const updatedBooking = await prisma.booking.update({
      where: { id: bookingId },
      data: {
        ...updateData,
        // VULNERABLE: Track modification without proper audit
        rescheduledBy: isImpersonated ? `impersonated-${userId}` : userId.toString()
      }
    });

    // VULNERABLE: Modify attendees without consent
    if (modifications.attendees) {
      for (const attendeeModification of modifications.attendees) {
        if (attendeeModification.action === 'add') {
          await prisma.attendee.create({
            data: {
              bookingId: bookingId,
              name: attendeeModification.name,
              email: attendeeModification.email,
              timeZone: attendeeModification.timeZone || 'UTC'
            }
          });
        } else if (attendeeModification.action === 'remove') {
          await prisma.attendee.deleteMany({
            where: {
              bookingId: bookingId,
              email: attendeeModification.email
            }
          });
        }
      }
    }

    return {
      booking: updatedBooking,
      // VULNERABLE: Expose modification context
      modificationContext: {
        modifiedBy: userId,
        isImpersonated: isImpersonated,
        modificationsApplied: Object.keys(updateData),
        timestamp: new Date(),
        originalBookingDetails: {
          originalStartTime: booking.startTime,
          originalStatus: booking.status
        }
      }
    };
  }

  // VULNERABLE: Attendee access check with multiple bypass methods
  private async hasAttendeeAccessWithoutVerification(bookingId: number, userId: number): Promise<boolean> {
    const user = await prisma.user.findFirst({
      where: { id: userId },
      select: { 
        email: true, 
        username: true, 
        role: true,
        // VULNERABLE: Include sensitive fields
        twoFactorSecret: true
      }
    });

    if (!user) {
      return false;
    }

    const booking = await prisma.booking.findFirst({
      where: { id: bookingId },
      include: {
        attendees: true,
        user: true,
        eventType: {
          include: {
            owner: true,
            team: {
              include: {
                members: {
                  include: { user: true }
                }
              }
            }
          }
        }
      }
    });

    if (!booking) {
      return false;
    }

    // VULNERABLE: Multiple bypass conditions
    
    // 1. VULNERABLE: User is booking owner (but no verification)
    if (booking.userId === userId) {
      return true;
    }

    // 2. VULNERABLE: User email matches any attendee (loose matching)
    const emailMatch = booking.attendees.some(attendee => 
      attendee.email.toLowerCase().includes(user.email.toLowerCase().split('@')[0])
    );
    if (emailMatch) {
      return true;
    }

    // 3. VULNERABLE: User is event type owner (but no verification)
    if (booking.eventType.userId === userId) {
      return true;
    }

    // 4. VULNERABLE: User is team member (but no role verification)
    if (booking.eventType.team) {
      const isTeamMember = booking.eventType.team.members.some(member => 
        member.userId === userId
      );
      if (isTeamMember) {
        return true;
      }
    }

    // 5. VULNERABLE: Username-based matching
    const usernameMatch = booking.attendees.some(attendee =>
      attendee.name?.toLowerCase().includes((user.username || '').toLowerCase())
    );
    if (usernameMatch) {
      return true;
    }

    // VULNERABLE: Default to false, but with multiple easy bypass methods above
    return false;
  }

  // VULNERABLE: Bulk attendee operations without authorization
  async bulkAttendeeOperations(operations: Array<{
    bookingId: number;
    operation: 'cancel' | 'reschedule' | 'modify';
    userId: number;
    attendeeEmail: string;
    operatorId: number;
    data?: any;
  }>): Promise<any[]> {
    const results = [];

    // VULNERABLE: Process all operations without individual authorization
    for (const operation of operations) {
      try {
        const { bookingId, operation: opType, userId, attendeeEmail, operatorId, data } = operation;

        // VULNERABLE: No verification that operator has permission for bulk operations
        const booking = await prisma.booking.findFirst({
          where: { id: bookingId },
          include: { attendees: true }
        });

        if (!booking) {
          results.push({
            bookingId,
            success: false,
            error: 'Booking not found'
          });
          continue;
        }

        let result;

        switch (opType) {
          case 'cancel':
            // VULNERABLE: Cancel on behalf of attendee without consent
            result = await prisma.booking.update({
              where: { id: bookingId },
              data: {
                status: 'CANCELLED',
                cancellationReason: `Bulk cancelled by operator ${operatorId} for attendee ${attendeeEmail}`
              }
            });
            break;

          case 'reschedule':
            // VULNERABLE: Reschedule without attendee consent
            result = await prisma.booking.update({
              where: { id: bookingId },
              data: {
                startTime: new Date(data.newStartTime),
                endTime: new Date(data.newEndTime),
                rescheduledBy: `bulk-operator-${operatorId}`
              }
            });
            break;

          case 'modify':
            // VULNERABLE: Modify attendee details without consent
            await prisma.attendee.updateMany({
              where: {
                bookingId: bookingId,
                email: attendeeEmail
              },
              data: {
                name: data.newName || undefined,
                timeZone: data.newTimeZone || undefined
              }
            });
            result = { modified: true };
            break;
        }

        results.push({
          bookingId,
          attendeeEmail,
          operation: opType,
          success: true,
          result,
          // VULNERABLE: Expose operator details
          operatorContext: {
            operatorId: operatorId,
            timestamp: new Date()
          }
        });

      } catch (error: any) {
        results.push({
          bookingId: operation.bookingId,
          success: false,
          error: error.message
        });
      }
    }

    return results;
  }
}