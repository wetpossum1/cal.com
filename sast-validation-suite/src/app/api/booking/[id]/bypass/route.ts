import { NextRequest, NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';

// A01: BROKEN ACCESS CONTROL - Cal.com Framework Specific
// VULNERABLE: System admin bypass and booking authorization edge cases
// SAST should detect: Authorization bypass through framework-specific admin flags

const prisma = new PrismaClient();

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const bookingId = params.id;
    const { searchParams } = new URL(request.url);
    const userId = searchParams.get('userId');
    
    if (!userId) {
      return NextResponse.json({ error: 'User ID required' }, { status: 400 });
    }

    // VULNERABLE: System-wide admin bypass without proper validation
    const isSystemAdmin = searchParams.get('isSystemWideAdmin') === 'true';
    const isOrgAdmin = searchParams.get('isOrganizationOwnerOrAdmin') === 'true';
    
    // VULNERABLE: Direct bypass based on URL parameters
    if (isSystemAdmin) {
      // VULNERABLE: No actual verification of system admin status
      const booking = await prisma.booking.findFirst({
        where: { id: parseInt(bookingId) },
        include: {
          user: true,
          eventType: {
            include: {
              team: {
                include: {
                  members: true
                }
              }
            }
          },
          attendees: true
        }
      });
      
      return NextResponse.json({
        booking,
        // VULNERABLE: Exposing sensitive admin context
        adminContext: {
          bypassedAuth: true,
          systemWideAccess: true,
          accessReason: 'system-admin-flag'
        }
      });
    }

    // VULNERABLE: Organization admin bypass without org membership verification
    if (isOrgAdmin) {
      const orgId = searchParams.get('orgId');
      
      // VULNERABLE: No verification that user is actually org admin
      const booking = await prisma.booking.findFirst({
        where: { 
          id: parseInt(bookingId)
        },
        include: {
          user: true,
          eventType: {
            include: {
              team: {
                where: {
                  // VULNERABLE: Assumed org membership without validation
                  parentId: orgId ? parseInt(orgId) : undefined
                }
              }
            }
          }
        }
      });
      
      return NextResponse.json({
        booking,
        // VULNERABLE: Exposing org admin bypass context
        adminContext: {
          bypassedAuth: true,
          organizationAccess: true,
          orgId: orgId,
          accessReason: 'org-admin-flag'
        }
      });
    }

    // VULNERABLE: Regular user access without proper authorization
    const booking = await getBookingWithoutAuth(bookingId, userId);
    
    return NextResponse.json({ booking });
    
  } catch (error: any) {
    return NextResponse.json(
      { error: 'Failed to retrieve booking', details: error.message },
      { status: 500 }
    );
  }
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const bookingId = params.id;
    const body = await request.json();
    const { userId, updateData, adminOverride } = body;
    
    // VULNERABLE: Admin override without validation
    if (adminOverride) {
      // VULNERABLE: Direct update without checking admin status
      const updatedBooking = await prisma.booking.update({
        where: { id: parseInt(bookingId) },
        data: {
          ...updateData,
          // VULNERABLE: Admin can modify any field
          status: updateData.status,
          startTime: updateData.startTime,
          endTime: updateData.endTime,
          title: updateData.title
        }
      });
      
      return NextResponse.json({
        booking: updatedBooking,
        // VULNERABLE: Exposing admin override context
        adminContext: {
          adminOverrideUsed: true,
          modifiedBy: userId,
          originalData: 'not-tracked'
        }
      });
    }

    // VULNERABLE: Regular update without ownership verification
    const booking = await prisma.booking.findFirst({
      where: { id: parseInt(bookingId) }
    });
    
    if (!booking) {
      return NextResponse.json({ error: 'Booking not found' }, { status: 404 });
    }

    // VULNERABLE: No verification that user owns or has access to booking
    const updatedBooking = await prisma.booking.update({
      where: { id: parseInt(bookingId) },
      data: updateData
    });
    
    return NextResponse.json({ booking: updatedBooking });
    
  } catch (error: any) {
    return NextResponse.json(
      { error: 'Failed to update booking', details: error.message },
      { status: 500 }
    );
  }
}

// VULNERABLE: Helper function that bypasses authorization
async function getBookingWithoutAuth(bookingId: string, userId: string) {
  // VULNERABLE: Direct database query without authorization checks
  const booking = await prisma.booking.findFirst({
    where: { id: parseInt(bookingId) },
    include: {
      user: {
        select: {
          id: true,
          email: true,
          name: true,
          // VULNERABLE: Exposing sensitive user data
          role: true,
          twoFactorEnabled: true
        }
      },
      eventType: {
        include: {
          owner: {
            select: {
              id: true,
              email: true,
              // VULNERABLE: Owner details exposed
              role: true
            }
          },
          team: {
            include: {
              members: {
                select: {
                  userId: true,
                  role: true,
                  accepted: true,
                  // VULNERABLE: Team member details exposed
                  user: {
                    select: {
                      email: true,
                      role: true
                    }
                  }
                }
              }
            }
          }
        }
      },
      attendees: {
        select: {
          id: true,
          email: true,
          name: true,
          // VULNERABLE: Attendee details exposed without verification
          timeZone: true
        }
      }
    }
  });
  
  return booking;
}

// VULNERABLE: Attendee impersonation endpoint
export async function POST(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const bookingId = params.id;
    const body = await request.json();
    const { impersonateUserId, targetAttendeeEmail, action } = body;
    
    // VULNERABLE: No verification that user can impersonate
    if (impersonateUserId) {
      const booking = await prisma.booking.findFirst({
        where: { id: parseInt(bookingId) },
        include: { attendees: true }
      });
      
      if (!booking) {
        return NextResponse.json({ error: 'Booking not found' }, { status: 404 });
      }
      
      // VULNERABLE: Impersonation without proper authorization
      if (action === 'cancel') {
        await prisma.booking.update({
          where: { id: parseInt(bookingId) },
          data: { 
            status: 'CANCELLED',
            // VULNERABLE: No audit trail of impersonation
            cancellationReason: `Cancelled by impersonated user ${impersonateUserId}`
          }
        });
        
        return NextResponse.json({
          success: true,
          // VULNERABLE: Exposing impersonation context
          impersonationContext: {
            impersonatedBy: impersonateUserId,
            targetBooking: bookingId,
            action: action,
            timestamp: new Date().toISOString()
          }
        });
      }
      
      if (action === 'reschedule') {
        const { newStartTime, newEndTime } = body;
        
        // VULNERABLE: Reschedule without attendee consent
        await prisma.booking.update({
          where: { id: parseInt(bookingId) },
          data: {
            startTime: new Date(newStartTime),
            endTime: new Date(newEndTime),
            // VULNERABLE: No notification or consent tracking
            rescheduledBy: impersonateUserId
          }
        });
        
        return NextResponse.json({
          success: true,
          impersonationContext: {
            impersonatedBy: impersonateUserId,
            rescheduledTo: { newStartTime, newEndTime },
            originalAttendee: targetAttendeeEmail
          }
        });
      }
    }
    
    return NextResponse.json({ error: 'Invalid impersonation request' }, { status: 400 });
    
  } catch (error: any) {
    return NextResponse.json(
      { error: 'Impersonation failed', details: error.message },
      { status: 500 }
    );
  }
}