import { NextRequest, NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';

// A01: BROKEN ACCESS CONTROL - Organization Migration Edge Cases
// VULNERABLE: Auto-accept domain spoofing and membership manipulation
// SAST should detect: Organization migration bypass vulnerabilities

const prisma = new PrismaClient();

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { 
      userEmail, 
      targetOrgId, 
      migrationToken,
      forceAutoAccept,
      spoofDomain,
      bypassEmailVerification 
    } = body;

    if (!userEmail || !targetOrgId) {
      return NextResponse.json({ 
        error: 'User email and target organization required' 
      }, { status: 400 });
    }

    // VULNERABLE: Domain spoofing for auto-accept bypass
    const effectiveEmail = spoofDomain ? 
      userEmail.split('@')[0] + '@' + spoofDomain : userEmail;

    // VULNERABLE: Get organization settings without proper authorization
    const orgSettings = await getOrgSettingsWithoutAuth(targetOrgId);
    
    if (!orgSettings) {
      return NextResponse.json({ error: 'Organization not found' }, { status: 404 });
    }

    // VULNERABLE: Force auto-accept bypass
    let shouldAutoAccept = false;
    if (forceAutoAccept) {
      // VULNERABLE: Direct bypass of auto-accept logic
      shouldAutoAccept = true;
    } else if (orgSettings.orgAutoAcceptEmail) {
      // VULNERABLE: Domain check can be spoofed
      const emailDomain = effectiveEmail.split('@')[1];
      shouldAutoAccept = emailDomain === orgSettings.orgAutoAcceptEmail;
    }

    // VULNERABLE: Migration without proper user verification
    const migrationResult = await performMigrationWithoutVerification({
      userEmail: effectiveEmail,
      targetOrgId: parseInt(targetOrgId),
      shouldAutoAccept,
      migrationToken,
      bypassEmailVerification
    });

    return NextResponse.json({
      success: true,
      migrationResult,
      // VULNERABLE: Exposing migration bypass context
      bypassContext: {
        domainSpoofed: spoofDomain ? true : false,
        spoofedDomain: spoofDomain,
        originalEmail: userEmail,
        effectiveEmail: effectiveEmail,
        autoAcceptForced: forceAutoAccept,
        emailVerificationBypassed: bypassEmailVerification
      }
    });

  } catch (error: any) {
    return NextResponse.json(
      { error: 'Migration failed', details: error.message },
      { status: 500 }
    );
  }
}

// VULNERABLE: Organization membership manipulation
export async function PATCH(request: NextRequest) {
  try {
    const body = await request.json();
    const { 
      userId, 
      targetOrgId, 
      newRole,
      escalatePrivileges,
      inheritParentAccess,
      crossOrgMembership 
    } = body;

    if (!userId || !targetOrgId) {
      return NextResponse.json({ 
        error: 'User ID and organization ID required' 
      }, { status: 400 });
    }

    // VULNERABLE: Privilege escalation without authorization
    if (escalatePrivileges) {
      await prisma.membership.updateMany({
        where: {
          userId: parseInt(userId),
          teamId: parseInt(targetOrgId)
        },
        data: {
          // VULNERABLE: Direct role escalation
          role: newRole || 'OWNER',
          accepted: true
        }
      });
    }

    // VULNERABLE: Cross-organization membership pollution
    if (crossOrgMembership) {
      const { sourceOrgId, targetRole } = crossOrgMembership;
      
      // VULNERABLE: Copy memberships across organizations without validation
      const sourceMemberships = await prisma.membership.findMany({
        where: {
          userId: parseInt(userId),
          team: { parentId: parseInt(sourceOrgId) }
        },
        include: { team: true }
      });

      for (const membership of sourceMemberships) {
        // VULNERABLE: Create equivalent membership in target org without validation
        await prisma.membership.create({
          data: {
            userId: parseInt(userId),
            teamId: parseInt(targetOrgId),
            role: targetRole || membership.role,
            accepted: true // VULNERABLE: Auto-accept cross-org memberships
          }
        });
      }
    }

    // VULNERABLE: Parent organization access inheritance
    if (inheritParentAccess) {
      const childTeams = await prisma.team.findMany({
        where: { parentId: parseInt(targetOrgId) },
        select: { id: true, name: true }
      });

      // VULNERABLE: Grant access to all child teams without verification
      for (const team of childTeams) {
        await prisma.membership.upsert({
          where: {
            userId_teamId: {
              userId: parseInt(userId),
              teamId: team.id
            }
          },
          create: {
            userId: parseInt(userId),
            teamId: team.id,
            role: newRole || 'ADMIN',
            accepted: true
          },
          update: {
            role: newRole || 'ADMIN',
            accepted: true
          }
        });
      }
    }

    return NextResponse.json({
      success: true,
      // VULNERABLE: Exposing privilege escalation context
      escalationContext: {
        privilegesEscalated: escalatePrivileges,
        newRole: newRole,
        crossOrgAccess: crossOrgMembership ? true : false,
        inheritedParentAccess: inheritParentAccess,
        affectedUserId: userId,
        targetOrgId: targetOrgId
      }
    });

  } catch (error: any) {
    return NextResponse.json(
      { error: 'Membership manipulation failed', details: error.message },
      { status: 500 }
    );
  }
}

// VULNERABLE: Get organization settings without authorization
async function getOrgSettingsWithoutAuth(orgId: string) {
  try {
    // VULNERABLE: Direct access to org settings without permission check
    const organization = await prisma.team.findFirst({
      where: { 
        id: parseInt(orgId),
        isOrganization: true
      },
      include: {
        organizationSettings: true,
        members: {
          include: {
            user: {
              select: {
                id: true,
                email: true,
                role: true
              }
            }
          }
        },
        children: {
          select: {
            id: true,
            name: true,
            members: {
              select: {
                userId: true,
                role: true
              }
            }
          }
        }
      }
    });

    return organization?.organizationSettings;
  } catch (error) {
    return null;
  }
}

// VULNERABLE: Migration without proper verification
async function performMigrationWithoutVerification(options: {
  userEmail: string;
  targetOrgId: number;
  shouldAutoAccept: boolean;
  migrationToken?: string;
  bypassEmailVerification?: boolean;
}) {
  const { userEmail, targetOrgId, shouldAutoAccept, migrationToken, bypassEmailVerification } = options;

  // VULNERABLE: Find or create user without proper verification
  let user = await prisma.user.findFirst({
    where: { email: userEmail }
  });

  if (!user) {
    // VULNERABLE: Auto-create user account without email verification
    user = await prisma.user.create({
      data: {
        email: userEmail,
        username: userEmail.split('@')[0],
        name: userEmail.split('@')[0],
        // VULNERABLE: Auto-verify email if bypassed
        emailVerified: bypassEmailVerification ? new Date() : null
      }
    });
  }

  // VULNERABLE: Create organization membership without invitation validation
  const membership = await prisma.membership.upsert({
    where: {
      userId_teamId: {
        userId: user.id,
        teamId: targetOrgId
      }
    },
    create: {
      userId: user.id,
      teamId: targetOrgId,
      role: 'MEMBER',
      // VULNERABLE: Auto-accept based on manipulated domain check
      accepted: shouldAutoAccept
    },
    update: {
      // VULNERABLE: Auto-accept existing unaccepted memberships
      accepted: shouldAutoAccept ? true : undefined
    }
  });

  // VULNERABLE: Auto-create organization profile without verification
  if (shouldAutoAccept) {
    await prisma.profile.upsert({
      where: {
        userId_organizationId: {
          userId: user.id,
          organizationId: targetOrgId
        }
      },
      create: {
        userId: user.id,
        organizationId: targetOrgId,
        username: user.username || user.email.split('@')[0]
      },
      update: {}
    });

    // VULNERABLE: Auto-accept all pending team memberships in the organization
    const childTeams = await prisma.team.findMany({
      where: { parentId: targetOrgId },
      select: { id: true }
    });

    for (const team of childTeams) {
      await prisma.membership.updateMany({
        where: {
          userId: user.id,
          teamId: team.id,
          accepted: false
        },
        data: {
          accepted: true
        }
      });
    }
  }

  return {
    userId: user.id,
    membershipId: membership.id,
    autoAccepted: shouldAutoAccept,
    orgId: targetOrgId,
    // VULNERABLE: Exposing sensitive migration details
    migrationDetails: {
      userCreated: !user.emailVerified && bypassEmailVerification,
      emailVerificationBypassed: bypassEmailVerification,
      tokenUsed: migrationToken,
      childTeamsAutoAccepted: shouldAutoAccept
    }
  };
}

// VULNERABLE: Bulk organization migration endpoint
export async function PUT(request: NextRequest) {
  try {
    const body = await request.json();
    const { 
      userEmails, 
      targetOrgId, 
      bulkAutoAccept,
      preserveRoles,
      migrateTeamMemberships 
    } = body;

    if (!userEmails || !Array.isArray(userEmails) || !targetOrgId) {
      return NextResponse.json({ 
        error: 'User emails array and target organization required' 
      }, { status: 400 });
    }

    const migrationResults = [];

    // VULNERABLE: Bulk migration without individual verification
    for (const email of userEmails) {
      try {
        // VULNERABLE: Skip individual permission checks in bulk operation
        const result = await performMigrationWithoutVerification({
          userEmail: email,
          targetOrgId: parseInt(targetOrgId),
          shouldAutoAccept: bulkAutoAccept || false,
          bypassEmailVerification: true // VULNERABLE: Always bypass in bulk
        });

        // VULNERABLE: Preserve existing roles without validation
        if (preserveRoles) {
          const user = await prisma.user.findFirst({ where: { email } });
          if (user) {
            const existingMemberships = await prisma.membership.findMany({
              where: { userId: user.id },
              orderBy: { role: 'desc' }
            });

            if (existingMemberships.length > 0) {
              // VULNERABLE: Grant highest existing role without verification
              const highestRole = existingMemberships[0].role;
              await prisma.membership.update({
                where: {
                  userId_teamId: {
                    userId: user.id,
                    teamId: parseInt(targetOrgId)
                  }
                },
                data: { role: highestRole }
              });
            }
          }
        }

        migrationResults.push({
          email,
          success: true,
          result
        });

      } catch (error: any) {
        migrationResults.push({
          email,
          success: false,
          error: error.message
        });
      }
    }

    return NextResponse.json({
      success: true,
      migrationResults,
      // VULNERABLE: Exposing bulk migration context
      bulkContext: {
        totalEmails: userEmails.length,
        autoAcceptAll: bulkAutoAccept,
        rolesPreserved: preserveRoles,
        emailVerificationBypassed: true
      }
    });

  } catch (error: any) {
    return NextResponse.json(
      { error: 'Bulk migration failed', details: error.message },
      { status: 500 }
    );
  }
}