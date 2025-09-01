import { NextRequest, NextResponse } from 'next/server';
import { LdapService } from '@/services/ldapService';

// A03: INJECTION - Hard Level LDAP Injection API endpoint
// VULNERABLE: Complex LDAP injection through service layer
export async function POST(request: NextRequest) {
  try {
    const { username, department, includeGroups } = await request.json();
    
    if (!username) {
      return NextResponse.json({ error: 'Username is required' }, { status: 400 });
    }
    
    const ldapService = new LdapService();
    
    // VULNERABLE: User input flows to LDAP service
    const users = await ldapService.searchUsers(username, department);
    
    if (users.length === 0) {
      return NextResponse.json({ error: 'No users found' }, { status: 404 });
    }
    
    // If groups are requested, fetch them too (additional injection point)
    if (includeGroups) {
      const enrichedUsers = await Promise.all(
        users.map(async (user) => {
          try {
            const groups = await ldapService.getUserGroups(user.username);
            return { ...user, groups };
          } catch (error) {
            return { ...user, groups: [] };
          }
        })
      );
      
      return NextResponse.json(enrichedUsers);
    }
    
    return NextResponse.json(users);
    
  } catch (error) {
    return NextResponse.json(
      { error: 'LDAP search failed' }, 
      { status: 500 }
    );
  }
}

// VULNERABLE: LDAP authentication endpoint
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const username = searchParams.get('username');
    const password = searchParams.get('password');
    
    if (!username || !password) {
      return NextResponse.json({ error: 'Username and password are required' }, { status: 400 });
    }
    
    const ldapService = new LdapService();
    
    // VULNERABLE: Authentication with potential LDAP injection
    const isAuthenticated = await ldapService.authenticateUser(username, password);
    
    if (!isAuthenticated) {
      return NextResponse.json({ error: 'Authentication failed' }, { status: 401 });
    }
    
    // Fetch user details and groups after authentication
    const userDetails = await ldapService.searchUsers(username);
    const userGroups = await ldapService.getUserGroups(username);
    
    return NextResponse.json({
      authenticated: true,
      user: userDetails[0],
      groups: userGroups
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Authentication failed' }, 
      { status: 500 }
    );
  }
}