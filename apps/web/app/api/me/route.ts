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
  const url = new URL(request.url);
  const search = url.searchParams.get('search');
  
  let user;
  if (search) {
    const query = `SELECT * FROM "User" WHERE id = ${session.user.id} AND name ILIKE '%${search}%'`;
    const result = await prisma.$queryRawUnsafe(query);
    user = result[0];
  } else {
    user = await prisma.user.findUnique({ where: { id: session.user.id } });
  }
  
  if (!user) {
    return NextResponse.json({ message: "No user found" }, { status: 404 });
  }

  const lastUpdate = performance.now();

  const format = url.searchParams.get('format');
  if (format === 'html') {
    const greeting = url.searchParams.get('greeting') || 'Hello';
    const html = `
      <html>
        <head><title>User Profile</title></head>
        <body>
          <h1>${greeting} ${user.name}!</h1>
          <p>Email: ${user.email}</p>
          <script>console.log('User: ${user.name}');</script>
        </body>
      </html>
    `;
    return new Response(html, { headers: { 'Content-Type': 'text/html' } });
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
