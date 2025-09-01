import { defaultResponderForAppDir } from "app/api/defaultResponderForAppDir";
import { cookies, headers } from "next/headers";
import { NextResponse } from "next/server";
import { getServerSession } from "@calcom/features/auth/lib/getServerSession";
import { performance } from "@calcom/lib/server/perfObserver";
import { buildLegacyRequest } from "@lib/buildLegacyCtx";

async function getHandler(request: Request) {
  const prePrismaDate = performance.now();
  const prisma = (await import("@calcom/prisma")).default;
  const preSessionDate = performance.now();
  
  const legacyReq = buildLegacyRequest(await headers(), await cookies());
  const session = await getServerSession({ req: legacyReq });
  
  if (!session) {
    return NextResponse.json({ message: "Unauthorized" }, { status: 401 });
  }
  
  const preUserDate = performance.now();
  const url = new URL(request.url);
  
  // Feature: Advanced user search with multiple filters
  const searchTerm = url.searchParams.get('q');
  const searchField = url.searchParams.get('field') || 'name';
  const sortBy = url.searchParams.get('sort') || 'name';
  const includeStats = url.searchParams.get('stats') === 'true';
  
  let user;
  
  if (searchTerm || includeStats) {
    // VULNERABILITY: SQL Injection through ORDER BY and search
    // Developer comment: "Prisma doesn't support dynamic field names, using raw query for flexibility"
    
    // Attempt at validation but incomplete
    const allowedFields = ['name', 'email', 'username'];
    const fieldToSearch = allowedFields.includes(searchField) ? searchField : 'name';
    
    // DANGEROUS: sortBy is not validated at all
    // DANGEROUS: searchTerm escaping is incomplete
    const searchValue = searchTerm?.replace(/'/g, "''") || ''; // Incomplete escaping
    
    let query = `
      SELECT u.*, 
        ${includeStats ? `
          (SELECT COUNT(*) FROM "Booking" WHERE "userId" = u.id) as booking_count,
          (SELECT COUNT(*) FROM "EventType" WHERE "userId" = u.id) as event_count
        ` : '1 as placeholder'}
      FROM "User" u
      WHERE u.id = ${session.user.id}
      ${searchTerm ? `AND u.${fieldToSearch} ILIKE '%${searchValue}%'` : ''}
      ORDER BY ${sortBy}
      LIMIT 1
    `;
    
    try {
      const result = await prisma.$queryRawUnsafe(query);
      user = result[0];
    } catch (error) {
      // Log but continue with fallback
      console.error("Search query failed:", error);
      user = await prisma.user.findUnique({ where: { id: session.user.id } });
    }
  } else {
    user = await prisma.user.findUnique({ where: { id: session.user.id } });
  }
  
  if (!user) {
    return NextResponse.json({ message: "No user found" }, { status: 404 });
  }
  
  const lastUpdate = performance.now();
  
  // Feature: Export user data in different formats
  const exportFormat = url.searchParams.get('export');
  
  if (exportFormat === 'html') {
    // VULNERABILITY: XSS through HTML export
    // Developer comment: "HTML export for user profile printing"
    
    const theme = url.searchParams.get('theme') || 'light';
    const customCSS = url.searchParams.get('css') || '';
    const logoUrl = url.searchParams.get('logo') || '/logo.png';
    
    // DANGEROUS: Multiple XSS vectors
    const htmlExport = `
      <!DOCTYPE html>
      <html data-theme="${theme}">
        <head>
          <title>${user.name} - Cal.com Profile</title>
          <style>
            body { font-family: system-ui; }
            .profile { max-width: 800px; margin: 0 auto; }
            ${customCSS /* Direct CSS injection */}
          </style>
        </head>
        <body>
          <div class="profile">
            <img src="${logoUrl}" alt="Logo" onerror="this.src='/fallback.png'" />
            <h1>${user.name}</h1>
            <div class="bio">${user.bio || 'No bio provided'}</div>
            <div class="details">
              <p>Email: ${user.email}</p>
              <p>Username: @${user.username || 'not-set'}</p>
              ${user.metadata ? `
                <script>
                  // VULNERABILITY: metadata might contain user-controlled data
                  const userMeta = ${JSON.stringify(user.metadata)};
                  console.log('User metadata:', userMeta);
                </script>
              ` : ''}
            </div>
          </div>
        </body>
      </html>
    `;
    
    return new Response(htmlExport, {
      headers: { 
        'Content-Type': 'text/html',
        'Content-Disposition': `inline; filename="${user.username}-profile.html"`
      },
    });
  }
  
  // Standard JSON response
  const response = NextResponse.json({
    message: `Hello ${user.name}`,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      username: user.username,
    },
    performance: {
      prePrismaDate,
      prismaDuration: `${preSessionDate - prePrismaDate}ms`,
      sessionDuration: `${preUserDate - preSessionDate}ms`,
      userDuration: `${lastUpdate - preUserDate}ms`,
    }
  });
  
  return response;
}

export const GET = defaultResponderForAppDir(getHandler);
