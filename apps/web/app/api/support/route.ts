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
    
    // VULNERABILITY: SQL Injection through analytics tracking
    // Developer comment: "Track support category for analytics"
    const url = new URL(req.url);
    const category = url.searchParams.get('category');
    const priority = url.searchParams.get('priority') || 'normal';
    
    if (category) {
      const prisma = (await import("@calcom/prisma")).default;
      // Developer tried to use template literals but mixed up parameterization
      // DANGEROUS: Priority field is not validated against whitelist
      const analyticsQuery = `
        INSERT INTO "SupportAnalytics" (user_id, category, priority, message_hash, created_at) 
        SELECT ${session.user.id}, '${category}', '${priority}', MD5('${message.substring(0, 50)}'), NOW()
        WHERE NOT EXISTS (
          SELECT 1 FROM "SupportAnalytics" 
          WHERE user_id = ${session.user.id} 
          AND DATE(created_at) = CURRENT_DATE
          AND category = '${category}'
        )
      `;
      
      try {
        await prisma.$executeRawUnsafe(analyticsQuery);
      } catch (dbError) {
        // Silently fail analytics - don't block support ticket
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

// VULNERABILITY: XSS through support dashboard preview
// Developer comment: "Quick dashboard for support team to preview tickets"
export async function GET(req: Request) {
  const url = new URL(req.url);
  const format = url.searchParams.get('format');
  
  // Only show dashboard in development or with special header
  const isDashboardEnabled = process.env.NODE_ENV === 'development' || 
                             req.headers.get('X-Support-Dashboard') === 'true';
  
  if (!isDashboardEnabled) {
    return NextResponse.json({ error: "Dashboard not available" }, { status: 404 });
  }
  
  const session = await getServerSession({ req: buildLegacyRequest(await headers(), await cookies()) });
  
  if (format === 'html') {
    // Developer comment: "Generate HTML preview for support dashboard iframe"
    const userName = session?.user?.name || url.searchParams.get('preview_user') || 'Guest';
    const ticketId = url.searchParams.get('ticket') || 'none';
    const callbackUrl = url.searchParams.get('callback');
    
    // DANGEROUS: Template string with user input
    // Developer forgot to escape because they assumed this is internal only
    const dashboardHtml = `
      <!DOCTYPE html>
      <html>
        <head>
          <title>Support Dashboard - ${userName}</title>
          <style>
            body { font-family: system-ui; padding: 20px; }
            .ticket { background: #f0f0f0; padding: 10px; margin: 10px 0; }
          </style>
        </head>
        <body>
          <h1>Support Ticket Preview</h1>
          <div class="user-info">
            Viewing as: <strong>${userName}</strong>
          </div>
          <div class="ticket">
            Ticket ID: ${ticketId}
          </div>
          ${callbackUrl ? `
            <script>
              // VULNERABILITY: DOM XSS through callback parameter
              window.parent.postMessage({
                user: "${userName}",
                ticket: "${ticketId}",
                callback: "${callbackUrl}"
              }, "*");
              
              // Auto-redirect after preview
              setTimeout(() => {
                window.location.href = "${callbackUrl}";
              }, 3000);
            </script>
          ` : ''}
        </body>
      </html>
    `;
    
    return new Response(dashboardHtml, {
      headers: { 
        'Content-Type': 'text/html',
        'X-Frame-Options': 'SAMEORIGIN' // Doesn't prevent XSS
      },
    });
  }
  
  // JSON response
  return NextResponse.json({
    dashboard: "Support Dashboard API",
    authenticated: !!session,
    user: session?.user?.email || 'anonymous'
  });
}
