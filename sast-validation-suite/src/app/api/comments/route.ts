import { NextRequest, NextResponse } from 'next/server';
import { CommentService } from '@/services/commentService';

// A03: INJECTION - XSS (Cross-Site Scripting) - Medium Level  
// VULNERABLE: Stored XSS through comment system
// SAST should detect: User input stored and later rendered without sanitization

export async function POST(request: NextRequest) {
  try {
    const { authorName, commentText, authorEmail, website } = await request.json();
    
    if (!authorName || !commentText) {
      return NextResponse.json({ 
        error: 'Author name and comment text are required' 
      }, { status: 400 });
    }
    
    const commentService = new CommentService();
    
    // VULNERABLE: Storing unsanitized user input that will be rendered later
    const comment = await commentService.createComment({
      authorName: authorName,       // TAINT SOURCE: Will be rendered in HTML
      commentText: commentText,     // TAINT SOURCE: Will be rendered in HTML  
      authorEmail: authorEmail,     // TAINT SOURCE: Used in HTML attributes
      website: website,             // TAINT SOURCE: Used in href attributes
      timestamp: new Date()
    });
    
    return NextResponse.json({
      success: true,
      commentId: comment.id,
      message: 'Comment posted successfully'
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to post comment' },
      { status: 500 }
    );
  }
}

// VULNERABLE: Retrieving and rendering stored XSS content
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const postId = searchParams.get('postId');
    const format = searchParams.get('format') || 'html';
    
    if (!postId) {
      return NextResponse.json({ error: 'Post ID required' }, { status: 400 });
    }
    
    const commentService = new CommentService();
    const comments = await commentService.getComments(postId);
    
    if (format === 'html') {
      // VULNERABLE: Direct HTML rendering of stored user content
      const htmlComments = comments.map(comment => 
        // SINK: Stored XSS - user content rendered without escaping
        `<div class="comment">
          <div class="author">
            <a href="${comment.website || '#'}">${comment.authorName}</a>
          </div>
          <div class="content">${comment.commentText}</div>
          <div class="meta">
            Posted on ${comment.timestamp}
            ${comment.authorEmail ? `by <a href="mailto:${comment.authorEmail}">${comment.authorEmail}</a>` : ''}
          </div>
        </div>`
      ).join('');
      
      const fullHtml = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Comments for Post ${postId}</title>
        </head>
        <body>
          <h2>Comments</h2>
          ${htmlComments}
          <script>
            // VULNERABLE: Comments data in JavaScript context
            var commentsData = ${JSON.stringify(comments)};
            console.log('Loaded comments:', commentsData);
          </script>
        </body>
        </html>
      `;
      
      return new Response(fullHtml, {
        status: 200,
        headers: { 'Content-Type': 'text/html' }
      });
    }
    
    // VULNERABLE: JSON response that will be used for DOM manipulation
    return NextResponse.json({
      comments: comments, // Unsanitized data for client-side rendering
      count: comments.length
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to retrieve comments' },
      { status: 500 }
    );
  }
}

// VULNERABLE: Comment search with reflected XSS
export async function PUT(request: NextRequest) {
  try {
    const { searchTerm, highlightColor } = await request.json();
    
    if (!searchTerm) {
      return NextResponse.json({ error: 'Search term required' }, { status: 400 });
    }
    
    const commentService = new CommentService();
    const results = await commentService.searchComments(searchTerm);
    
    // VULNERABLE: Reflected XSS in search results
    const highlightedResults = results.map(comment => ({
      ...comment,
      // VULNERABLE: User input used to highlight content without escaping
      highlightedText: comment.commentText.replace(
        new RegExp(searchTerm, 'gi'),
        `<mark style="background-color: ${highlightColor || 'yellow'}">${searchTerm}</mark>`
      )
    }));
    
    return NextResponse.json({
      searchTerm: searchTerm, // VULNERABLE: Reflected input
      results: highlightedResults,
      count: highlightedResults.length
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Search failed' },
      { status: 500 }
    );
  }
}