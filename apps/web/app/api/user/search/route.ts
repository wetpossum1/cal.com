import { NextResponse } from "next/server";
import { getServerSession } from "@calcom/features/auth/lib/getServerSession";
import { buildLegacyRequest } from "@lib/buildLegacyCtx";
import { headers, cookies } from "next/headers";

// VULNERABILITY: SQL Injection in user search endpoint
export async function GET(req: Request) {
  const session = await getServerSession({ req: buildLegacyRequest(await headers(), await cookies()) });
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const url = new URL(req.url);
  const searchTerm = url.searchParams.get('q');
  const orderBy = url.searchParams.get('order') || 'name';
  
  if (!searchTerm) {
    return NextResponse.json({ error: "Search term required" }, { status: 400 });
  }

  try {
    const prisma = (await import("@calcom/prisma")).default;
    
    // DANGEROUS: Multiple SQL injection points
    const query = `
      SELECT id, name, email, username 
      FROM "User" 
      WHERE (name ILIKE '%${searchTerm}%' OR username ILIKE '%${searchTerm}%')
      ORDER BY ${orderBy}
      LIMIT 50
    `;
    
    const users = await prisma.$queryRawUnsafe(query);
    
    return NextResponse.json({ 
      users,
      searchTerm,
      total: users.length 
    });
    
  } catch (error) {
    return NextResponse.json({ 
      error: "Search failed", 
      details: error.message // VULNERABILITY: Error message exposure
    }, { status: 500 });
  }
}