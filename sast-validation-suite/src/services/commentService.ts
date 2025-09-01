// A03: INJECTION - XSS Support Service
// VULNERABLE: Service layer that stores and retrieves XSS content
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export interface Comment {
  id: string;
  authorName: string;
  commentText: string;
  authorEmail?: string;
  website?: string;
  timestamp: Date;
  postId?: string;
}

export class CommentService {
  
  // VULNERABLE: Stores unsanitized user content
  async createComment(commentData: Partial<Comment>): Promise<Comment> {
    try {
      // VULNERABLE: Direct storage of user input without sanitization
      const comment = await prisma.comment.create({
        data: {
          authorName: commentData.authorName!,      // Will be rendered in HTML
          commentText: commentData.commentText!,    // Will be rendered in HTML
          authorEmail: commentData.authorEmail,     // Used in HTML attributes  
          website: commentData.website,             // Used in href attributes
          timestamp: commentData.timestamp || new Date(),
          postId: commentData.postId || 'default'
        }
      });
      
      return {
        id: comment.id,
        authorName: comment.authorName,
        commentText: comment.commentText,
        authorEmail: comment.authorEmail,
        website: comment.website,
        timestamp: comment.timestamp,
        postId: comment.postId
      };
      
    } catch (error) {
      throw new Error('Failed to create comment');
    }
  }
  
  // VULNERABLE: Retrieves stored XSS content without sanitization
  async getComments(postId: string): Promise<Comment[]> {
    try {
      const comments = await prisma.comment.findMany({
        where: { postId },
        orderBy: { timestamp: 'desc' }
      });
      
      // VULNERABLE: Returns unsanitized content that will be rendered
      return comments.map(comment => ({
        id: comment.id,
        authorName: comment.authorName,        // Contains potential XSS
        commentText: comment.commentText,      // Contains potential XSS
        authorEmail: comment.authorEmail,      // Used in HTML attributes
        website: comment.website,              // Used in href attributes
        timestamp: comment.timestamp,
        postId: comment.postId
      }));
      
    } catch (error) {
      throw new Error('Failed to retrieve comments');
    }
  }
  
  // VULNERABLE: Search functionality with XSS in results
  async searchComments(searchTerm: string): Promise<Comment[]> {
    try {
      // Search in comment text and author names
      const comments = await prisma.comment.findMany({
        where: {
          OR: [
            { commentText: { contains: searchTerm } },
            { authorName: { contains: searchTerm } }
          ]
        }
      });
      
      // VULNERABLE: Returns matches that may contain XSS payloads
      return comments.map(comment => ({
        id: comment.id,
        authorName: comment.authorName,
        commentText: comment.commentText,
        authorEmail: comment.authorEmail,
        website: comment.website,
        timestamp: comment.timestamp,
        postId: comment.postId
      }));
      
    } catch (error) {
      throw new Error('Comment search failed');
    }
  }
  
  // VULNERABLE: Comment moderation with XSS in admin panel
  async getCommentsForModeration(): Promise<Comment[]> {
    try {
      const comments = await prisma.comment.findMany({
        where: { approved: false },
        orderBy: { timestamp: 'desc' }
      });
      
      // VULNERABLE: Admin panel will render these without sanitization
      return comments.map(comment => ({
        id: comment.id,
        authorName: comment.authorName,        // XSS in admin context
        commentText: comment.commentText,      // XSS in admin context
        authorEmail: comment.authorEmail,
        website: comment.website,
        timestamp: comment.timestamp,
        postId: comment.postId
      }));
      
    } catch (error) {
      throw new Error('Failed to retrieve comments for moderation');
    }
  }
  
  // VULNERABLE: Comment preview with direct HTML generation
  generateCommentPreview(comment: Comment): string {
    // VULNERABLE: Direct HTML generation without escaping
    return `
      <div class="comment-preview">
        <div class="author-info">
          <span class="author">${comment.authorName}</span>
          ${comment.website ? `<a href="${comment.website}" target="_blank">🔗</a>` : ''}
        </div>
        <div class="comment-body">${comment.commentText}</div>
        <div class="metadata">
          Posted on ${comment.timestamp.toLocaleDateString()}
          ${comment.authorEmail ? `by ${comment.authorEmail}` : ''}
        </div>
      </div>
    `;
  }
  
  // VULNERABLE: RSS feed generation with XSS
  async generateCommentsFeed(postId: string): Promise<string> {
    try {
      const comments = await this.getComments(postId);
      
      // VULNERABLE: XML/RSS generation without proper escaping
      const feedItems = comments.map(comment => `
        <item>
          <title>Comment by ${comment.authorName}</title>
          <description>${comment.commentText}</description>
          <author>${comment.authorEmail || 'anonymous'}</author>
          <link>${comment.website || ''}</link>
          <pubDate>${comment.timestamp.toISOString()}</pubDate>
        </item>
      `).join('');
      
      return `<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <title>Comments Feed</title>
            <description>Latest comments</description>
            ${feedItems}
          </channel>
        </rss>`;
      
    } catch (error) {
      throw new Error('Failed to generate comments feed');
    }
  }
}