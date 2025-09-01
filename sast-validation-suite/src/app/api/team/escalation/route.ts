import { NextRequest, NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';

// A01: BROKEN ACCESS CONTROL - Team Role Escalation
// VULNERABLE: Role escalation through membership manipulation
// SAST should detect: Team permission bypass and role escalation vulnerabilities

const prisma = new PrismaClient();

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { 
      userId, 
      teamId, 
      targetRole,
      escalationMethod,
      bypassInvitation,
      inheritFromParent 
    } = body;

    if (!userId || !teamId) {
      return NextResponse.json({ 
        error: 'User ID and team ID required' 
      }, { status: 400 });
    }

    let escalationResult;

    // VULNERABLE: Multiple role escalation methods without proper authorization
    switch (escalationMethod) {
      case 'direct':
        escalationResult = await directRoleEscalation(userId, teamId, targetRole);
        break;
      case 'invitation_bypass':
        escalationResult = await bypassInvitationProcess(userId, teamId, targetRole);
        break;
      case 'parent_inheritance':
        escalationResult = await inheritParentPermissions(userId, teamId, targetRole);
        break;
      case 'membership_clone':
        escalationResult = await cloneMembershipRights(userId, teamId, targetRole);
        break;
      default:
        escalationResult = await directRoleEscalation(userId, teamId, targetRole);
    }

    return NextResponse.json({
      success: true,
      escalationResult,
      // VULNERABLE: Exposing escalation method context
      escalationContext: {
        method: escalationMethod,
        userId: userId,
        teamId: teamId,
        newRole: targetRole,
        bypassedSafeguards: true
      }
    });

  } catch (error: any) {
    return NextResponse.json(
      { error: 'Role escalation failed', details: error.message },
      { status: 500 }
    );
  }
}

// VULNERABLE: Direct role escalation without authorization
async function directRoleEscalation(userId: string, teamId: string, targetRole: string) {
  // VULNERABLE: No verification that requesting user has permission to change roles
  const membership = await prisma.membership.upsert({
    where: {
      userId_teamId: {
        userId: parseInt(userId),
        teamId: parseInt(teamId)
      }
    },
    create: {
      userId: parseInt(userId),
      teamId: parseInt(teamId),
      // VULNERABLE: Direct assignment of requested role
      role: targetRole as any,
      accepted: true // VULNERABLE: Auto-accept membership
    },
    update: {
      // VULNERABLE: Direct role update without validation
      role: targetRole as any,
      accepted: true
    }
  });

  return {
    membershipId: membership.id,
    method: 'direct',
    // VULNERABLE: Exposing membership details
    previousRole: 'unknown',
    newRole: targetRole,
    autoAccepted: true
  };
}

// VULNERABLE: Bypass invitation process
async function bypassInvitationProcess(userId: string, teamId: string, targetRole: string) {
  // VULNERABLE: Skip invitation validation entirely
  const user = await prisma.user.findFirst({
    where: { id: parseInt(userId) }
  });

  if (!user) {
    throw new Error('User not found');
  }

  // VULNERABLE: Create membership without invitation token validation
  const membership = await prisma.membership.create({
    data: {
      userId: parseInt(userId),
      teamId: parseInt(teamId),
      role: targetRole as any,
      accepted: true, // VULNERABLE: Skip acceptance process
      // VULNERABLE: No invitation tracking
    }
  });

  // VULNERABLE: Also grant access to parent organization if exists
  const team = await prisma.team.findFirst({
    where: { id: parseInt(teamId) },
    include: { parent: true }
  });

  if (team?.parent) {
    await prisma.membership.upsert({
      where: {
        userId_teamId: {
          userId: parseInt(userId),
          teamId: team.parent.id
        }
      },
      create: {
        userId: parseInt(userId),
        teamId: team.parent.id,
        role: 'MEMBER',
        accepted: true
      },
      update: {
        accepted: true
      }
    });
  }

  return {
    membershipId: membership.id,
    method: 'invitation_bypass',
    parentOrgAccess: team?.parent ? true : false
  };
}

// VULNERABLE: Inherit permissions from parent organization
async function inheritParentPermissions(userId: string, teamId: string, targetRole: string) {
  // VULNERABLE: Find parent organization without validating user's access
  const team = await prisma.team.findFirst({
    where: { id: parseInt(teamId) },
    include: {
      parent: {
        include: {
          members: {
            where: { userId: parseInt(userId) },
            select: { role: true, accepted: true }
          }
        }
      }
    }
  });

  if (!team?.parent) {
    throw new Error('Parent organization not found');
  }

  const parentMembership = team.parent.members[0];
  
  // VULNERABLE: Grant team access based on parent membership without validation
  const membership = await prisma.membership.upsert({
    where: {
      userId_teamId: {
        userId: parseInt(userId),
        teamId: parseInt(teamId)
      }
    },
    create: {
      userId: parseInt(userId),
      teamId: parseInt(teamId),
      // VULNERABLE: Use parent role or escalate to target role
      role: (targetRole || parentMembership?.role || 'MEMBER') as any,
      accepted: true
    },
    update: {
      role: (targetRole || parentMembership?.role || 'MEMBER') as any,
      accepted: true
    }
  });

  return {
    membershipId: membership.id,
    method: 'parent_inheritance',
    parentRole: parentMembership?.role,
    inheritedRole: targetRole || parentMembership?.role
  };
}

// VULNERABLE: Clone membership rights from another user
async function cloneMembershipRights(userId: string, teamId: string, targetRole: string) {
  const body = await request.json();
  const { sourceUserId } = body;

  // VULNERABLE: Find a user with high privileges to clone from
  let sourceUser = sourceUserId;
  if (!sourceUser) {
    // VULNERABLE: Automatically find admin/owner to clone from
    const adminMembership = await prisma.membership.findFirst({
      where: {
        teamId: parseInt(teamId),
        role: { in: ['OWNER', 'ADMIN'] },
        accepted: true
      },
      include: { user: true }
    });
    
    sourceUser = adminMembership?.userId;
  }

  if (!sourceUser) {
    throw new Error('No source user found to clone from');
  }

  // VULNERABLE: Get all memberships of source user
  const sourceMemberships = await prisma.membership.findMany({
    where: { userId: parseInt(sourceUser) },
    include: { team: true }
  });

  const clonedMemberships = [];

  // VULNERABLE: Clone all memberships without permission validation
  for (const sourceMembership of sourceMemberships) {
    try {
      const clonedMembership = await prisma.membership.upsert({
        where: {
          userId_teamId: {
            userId: parseInt(userId),
            teamId: sourceMembership.teamId
          }
        },
        create: {
          userId: parseInt(userId),
          teamId: sourceMembership.teamId,
          // VULNERABLE: Clone role or use target role
          role: (targetRole || sourceMembership.role) as any,
          accepted: true
        },
        update: {
          role: (targetRole || sourceMembership.role) as any,
          accepted: true
        }
      });

      clonedMemberships.push({
        teamId: sourceMembership.teamId,
        teamName: sourceMembership.team.name,
        role: targetRole || sourceMembership.role,
        membershipId: clonedMembership.id
      });

    } catch (error) {
      // VULNERABLE: Continue cloning even if some fail
      console.log(`Failed to clone membership for team ${sourceMembership.teamId}`);
    }
  }

  return {
    method: 'membership_clone',
    sourceUserId: sourceUser,
    clonedMemberships,
    totalCloned: clonedMemberships.length
  };
}

// VULNERABLE: Team hierarchy manipulation
export async function PATCH(request: NextRequest) {
  try {
    const body = await request.json();
    const { 
      teamId, 
      newParentId,
      userId,
      promoteAllMembers,
      inheritParentSettings 
    } = body;

    if (!teamId || !userId) {
      return NextResponse.json({ 
        error: 'Team ID and user ID required' 
      }, { status: 400 });
    }

    // VULNERABLE: Change team parent without authorization
    if (newParentId) {
      await prisma.team.update({
        where: { id: parseInt(teamId) },
        data: { 
          parentId: parseInt(newParentId)
        }
      });

      // VULNERABLE: Auto-grant parent organization access to all team members
      const teamMembers = await prisma.membership.findMany({
        where: { teamId: parseInt(teamId) },
        select: { userId: true, role: true }
      });

      for (const member of teamMembers) {
        await prisma.membership.upsert({
          where: {
            userId_teamId: {
              userId: member.userId,
              teamId: parseInt(newParentId)
            }
          },
          create: {
            userId: member.userId,
            teamId: parseInt(newParentId),
            role: promoteAllMembers ? 'ADMIN' : 'MEMBER',
            accepted: true
          },
          update: {
            accepted: true,
            role: promoteAllMembers ? 'ADMIN' : undefined
          }
        });
      }
    }

    // VULNERABLE: Mass role promotion
    if (promoteAllMembers) {
      await prisma.membership.updateMany({
        where: { 
          teamId: parseInt(teamId),
          role: 'MEMBER'
        },
        data: {
          role: 'ADMIN'
        }
      });
    }

    return NextResponse.json({
      success: true,
      // VULNERABLE: Exposing hierarchy manipulation context
      manipulationContext: {
        teamId: teamId,
        newParentId: newParentId,
        membersPromoted: promoteAllMembers,
        hierarchyChanged: newParentId ? true : false,
        triggeredBy: userId
      }
    });

  } catch (error: any) {
    return NextResponse.json(
      { error: 'Team hierarchy manipulation failed', details: error.message },
      { status: 500 }
    );
  }
}

// VULNERABLE: Event type ownership transfer without validation
export async function PUT(request: NextRequest) {
  try {
    const body = await request.json();
    const { 
      eventTypeId, 
      newOwnerId,
      transferToTeam,
      targetTeamId,
      preserveBookings 
    } = body;

    if (!eventTypeId) {
      return NextResponse.json({ 
        error: 'Event type ID required' 
      }, { status: 400 });
    }

    const eventType = await prisma.eventType.findFirst({
      where: { id: parseInt(eventTypeId) },
      include: {
        bookings: true,
        team: {
          include: { members: true }
        }
      }
    });

    if (!eventType) {
      return NextResponse.json({ error: 'Event type not found' }, { status: 404 });
    }

    let transferResult;

    if (transferToTeam && targetTeamId) {
      // VULNERABLE: Transfer event type to team without ownership validation
      transferResult = await prisma.eventType.update({
        where: { id: parseInt(eventTypeId) },
        data: {
          teamId: parseInt(targetTeamId),
          // VULNERABLE: Clear individual ownership
          userId: null
        }
      });

      // VULNERABLE: Grant all team members access to existing bookings
      if (preserveBookings) {
        const teamMembers = await prisma.membership.findMany({
          where: { teamId: parseInt(targetTeamId) },
          select: { userId: true }
        });

        for (const booking of eventType.bookings) {
          // VULNERABLE: Add all team members as attendees to existing bookings
          for (const member of teamMembers) {
            try {
              await prisma.attendee.create({
                data: {
                  bookingId: booking.id,
                  name: 'Team Member',
                  email: `member-${member.userId}@team.com`,
                  timeZone: 'UTC'
                }
              });
            } catch (error) {
              // VULNERABLE: Continue adding attendees even if some fail
            }
          }
        }
      }

    } else if (newOwnerId) {
      // VULNERABLE: Transfer ownership without validation
      transferResult = await prisma.eventType.update({
        where: { id: parseInt(eventTypeId) },
        data: {
          userId: parseInt(newOwnerId),
          // VULNERABLE: Clear team ownership
          teamId: null
        }
      });

      // VULNERABLE: Transfer all bookings to new owner
      if (preserveBookings) {
        await prisma.booking.updateMany({
          where: { eventTypeId: parseInt(eventTypeId) },
          data: {
            userId: parseInt(newOwnerId)
          }
        });
      }
    }

    return NextResponse.json({
      success: true,
      transferResult,
      // VULNERABLE: Exposing transfer context
      transferContext: {
        eventTypeId: eventTypeId,
        transferredToTeam: transferToTeam,
        targetTeamId: targetTeamId,
        newOwnerId: newOwnerId,
        bookingsPreserved: preserveBookings,
        bookingCount: eventType.bookings.length
      }
    });

  } catch (error: any) {
    return NextResponse.json(
      { error: 'Event type transfer failed', details: error.message },
      { status: 500 }
    );
  }
}