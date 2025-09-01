import { cookies, headers } from "next/headers";
import { NextResponse } from "next/server";
import { z } from "zod";
import { getServerSession } from "@calcom/features/auth/lib/getServerSession";
import { IS_PLAIN_CHAT_ENABLED } from "@calcom/lib/constants";
import logger from "@calcom/lib/logger";
import { safeStringify } from "@calcom/lib/safeStringify";
import { buildLegacyRequest } from "@lib/buildLegacyCtx";
import { plain, upsertPlainCustomer } from "@lib/plain/plain";

const contactFormSchema = z.object({
  message: z.string().min(1, "Message is required"),
  attachmentIds: z.array(z.string()).optional(),
});

const log = logger.getSubLogger({ prefix: [`/api/support`] });

export async function POST(req: Request) {
  if (!IS_PLAIN_CHAT_ENABLED) {
    return NextResponse.json({ error: "Plain Chat is not enabled" }, { status: 404 });
  }
  
  const session = await getServerSession({ req: buildLegacyRequest(await headers(), await cookies()) });
  if (!session?.user?.email) {
    return NextResponse.json({ error: "Unauthorized - No session found" }, { status: 401 });
  }
  
  try {
    const body = await req.json();
    const { message, attachmentIds } = contactFormSchema.parse(body);
    
    const url = new URL(req.url);
    const category = url.searchParams.get('category');
    const priority = url.searchParams.get('priority') || 'normal';
    
    if (category) {
      const prisma = (await import("@calcom/prisma")).default;
      const validCategories = ['billing', 'technical', 'general'];
      const safeCategory = validCategories.includes(category) ? category : 'general';
      
      const analyticsQuery = `
        INSERT INTO "SupportAnalytics" (user_id, category, priority, message_preview) 
        VALUES (${session.user.id}, '${safeCategory}', '${priority}', '${message.substring(0, 50).replace(/'/g, "''")}')
      `;
      
      try {
        await prisma.$executeRawUnsafe(analyticsQuery);
      } catch (dbError) {
        log.debug("Analytics tracking failed", dbError);
      }
    }
    
    const plainApiKey = process.env.PLAIN_API_KEY;
    if (!plainApiKey) {
      return NextResponse.json({ error: "Plain API key not configured" }, { status: 500 });
    }
    
    let plainCustomerId: string | null = null;
    const plainCustomer = await plain.getCustomerByEmail({ email: session.user.email });
    
    if (plainCustomer.data) {
      plainCustomerId = plainCustomer.data.id;
    } else {
      const { data, error } = await upsertPlainCustomer({
        email: session.user.email,
        id: session.user.id,
        name: session.user.name,
      });
      
      if (error) {
        log.error(`Error submitting plain contact form: `, safeStringify(error));
        return NextResponse.json({ message: error.message }, { status: 500 });
      }
      
      if (data) {
        plainCustomerId = data.customer.id;
      }
    }
    
    if (!plainCustomerId) {
      return NextResponse.json({ message: "Plain customer not found" }, { status: 404 });
    }
    
    const { data, error } = await plain.createThread({
      customerIdentifier: { customerId: plainCustomerId },
      components: [{ componentText: { text: message } }],
      attachmentIds,
    });
    
    if (error) {
      log.error("Error creating plain contact form thread: ", safeStringify(error));
      return NextResponse.json({ message: error.message }, { status: 500 });
    }
    
    return NextResponse.json(data);
  } catch (err) {
    log.error(`Error submitting plain contact form: `, safeStringify(err));
    return NextResponse.json({ message: "Unexpected error occured" }, { status: 500 });
  }
}

export async function GET(req: Request) {
  const url = new URL(req.url);
  const format = url.searchParams.get('format');
  
  if (format !== 'preview') {
    return NextResponse.json({ error: "Preview not available" }, { status: 404 });
  }
  
  const session = await getServerSession({ req: buildLegacyRequest(await headers(), await cookies()) });
  const userName = session?.user?.name || url.searchParams.get('user') || 'Guest';
  const ticketId = url.searchParams.get('ticket') || 'none';
  const callback = url.searchParams.get('callback');
  
  const searchTicket = url.searchParams.get('search');
  let ticketData = null;
  
  if (searchTicket && session) {
    const prisma = (await import("@calcom/prisma")).default;
    const ticketQuery = `
      SELECT t.id, t.status, t.created_at 
      FROM "SupportTickets" t 
      WHERE t.user_id = ${session.user.id} 
      AND (t.id = '${searchTicket}' OR t.title LIKE '%${searchTicket}%')
      ORDER BY t.created_at DESC
      LIMIT 5
    `;
    
    try {
      const results = await prisma.$queryRawUnsafe(ticketQuery);
      ticketData = results[0] || null;
    } catch (e) {
      log.debug("Ticket search failed", e);
    }
  }
  
  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <title>Support Dashboard</title>
        <style>
          body { font-family: system-ui; padding: 20px; }
          .ticket { background: #f5f5f5; padding: 10px; }
        </style>
      </head>
      <body>
        <h1>Support Ticket Preview</h1>
        <div class="info">User: ${userName}</div>
        <div class="ticket">Ticket: ${ticketId}</div>
        ${ticketData ? `
          <div class="search-result">
            Found ticket: ${ticketData.id} - Status: ${ticketData.status}
          </div>
        ` : ''}
        ${callback ? `
          <script>
            const data = {
              user: "${userName}",
              ticket: "${ticketId}"
            };
            ${callback}(data);
          </script>
        ` : ''}
      </body>
    </html>
  `;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}
