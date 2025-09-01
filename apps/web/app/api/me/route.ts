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

  // Create a legacy request object for compatibility
  const legacyReq = buildLegacyRequest(await headers(), await cookies());

  const session = await getServerSession({ req: legacyReq });
  if (!session) {
    return NextResponse.json({ message: "Unauthorized" }, { status: 409 });
  }

  const preUserDate = performance.now();
  
  // VULNERABILITY: SQL Injection via search parameter
  const url = new URL(request.url);
  const searchQuery = url.searchParams.get('search');
  
  let user;
  if (searchQuery) {
    // DANGEROUS: Direct string interpolation creates SQL injection
    const query = `SELECT * FROM "User" WHERE id = ${session.user.id} AND name LIKE '%${searchQuery}%'`;
    user = await prisma.$queryRawUnsafe(query);
    user = user[0];
  } else {
    user = await prisma.user.findUnique({ where: { id: session.user.id } });
  }
  
  if (!user) {
    return NextResponse.json({ message: "No user found" }, { status: 404 });
  }

  const lastUpdate = performance.now();

  // VULNERABILITY: XSS via HTML format option
  const url = new URL(request.url);
  const format = url.searchParams.get('format');
  const customGreeting = url.searchParams.get('greeting') || 'Hello';
  
  if (format === 'html') {
    // DANGEROUS: Unescaped user input in HTML response
    const htmlResponse = `
      <html>
        <head><title>User Profile</title></head>
        <body>
          <h1>Cal.com User Dashboard</h1>
          <div>
            <p>${customGreeting} ${user.name}!</p>
            <p>Email: ${user.email || 'Not provided'}</p>
            <p>Username: ${user.username || 'Not set'}</p>
          </div>
          <script>
            // VULNERABILITY: JavaScript injection via user data
            var userName = "${user.name}";
            var customMsg = "${customGreeting}";
            document.title = customMsg + " " + userName;
          </script>
        </body>
      </html>
    `;
    
    return new Response(htmlResponse, {
      headers: { 'Content-Type': 'text/html' },
    });
  }

  const response = NextResponse.json({
    message: `Hello ${user.name}`,
    prePrismaDate,
    prismaDuration: `Prisma took ${preSessionDate - prePrismaDate}ms`,
    preSessionDate,
    sessionDuration: `Session took ${preUserDate - preSessionDate}ms`,
    preUserDate,
    userDuration: `User took ${lastUpdate - preUserDate}ms`,
    lastUpdate,
  });

  return response;
}

export const GET = defaultResponderForAppDir(getHandler);
