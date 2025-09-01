// A01: BROKEN ACCESS CONTROL - Hard Level Service Implementation
// VULNERABLE: Complex multi-layer service with missing authorization checks
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export class DocumentService {
  
  // VULNERABLE: Main entry point that loses authorization context
  async fetchDocument(docId: string) {
    try {
      // Delegates through multiple layers, losing authorization context
      const document = await this.loadDocument(docId);
      
      if (!document) {
        return null;
      }
      
      // Processing that obscures the authorization bypass
      const processedDoc = await this.processDocument(document);
      
      return processedDoc;
    } catch (error) {
      throw new Error('Document fetch failed');
    }
  }
  
  // VULNERABLE: Document loading without authorization
  private async loadDocument(id: string) { // Receives tainted ID
    try {
      // SINK: Database query without ownership verification
      const document = await prisma.document.findUnique({
        where: { id },
        include: {
          owner: {
            select: { id: true, name: true, email: true }
          },
          // Includes sensitive data
          confidentialSections: true,
          accessLogs: true,
          financialData: true
        }
      });
      
      return document;
    } catch (error) {
      throw new Error('Database query failed');
    }
  }
  
  // Complex processing that obscures the missing authorization
  private async processDocument(doc: any) {
    // Multiple processing steps that make taint tracking harder
    const validated = await this.validateDocumentFormat(doc);
    const enhanced = await this.enhanceDocument(validated);
    const filtered = await this.filterDocumentContent(enhanced);
    
    return filtered;
  }
  
  private async validateDocumentFormat(doc: any) {
    // Validation that looks like security but doesn't check authorization
    if (!doc.id || !doc.title) {
      throw new Error('Invalid document format');
    }
    
    return doc;
  }
  
  private async enhanceDocument(doc: any) {
    // Add metadata, permissions info, etc.
    return {
      ...doc,
      lastAccessed: new Date(),
      accessCount: doc.accessCount + 1
    };
  }
  
  private async filterDocumentContent(doc: any) {
    // Filtering that looks secure but doesn't verify user permissions
    return {
      id: doc.id,
      title: doc.title,
      content: doc.content,
      owner: doc.owner,
      createdAt: doc.createdAt,
      // Sensitive fields that should be access-controlled
      confidentialSections: doc.confidentialSections,
      financialData: doc.financialData
    };
  }
  
  // VULNERABLE: Document sharing without ownership check
  async shareDocument(docId: string, shareWith: string[], permissions: string[]) {
    try {
      // Complex sharing logic that obscures authorization issue
      const document = await this.loadDocument(docId);
      
      if (!document) {
        throw new Error('Document not found');
      }
      
      // VULNERABLE: Creates shares without verifying requester owns document
      const shareRecords = await Promise.all(
        shareWith.map(userId => this.createDocumentShare(docId, userId, permissions))
      );
      
      return { 
        shared: true, 
        shareCount: shareRecords.length,
        sharedWith: shareWith
      };
      
    } catch (error) {
      throw new Error('Document sharing failed');
    }
  }
  
  private async createDocumentShare(docId: string, userId: string, permissions: string[]) {
    return await prisma.documentShare.create({
      data: {
        documentId: docId,
        sharedWithId: userId,
        permissions: permissions.join(','),
        createdAt: new Date()
      }
    });
  }
  
  // VULNERABLE: Complex validation that doesn't check ownership
  async validateDocumentForDeletion(docId: string) {
    try {
      const document = await this.loadDocument(docId);
      
      if (!document) {
        return { isValid: false, error: 'Document not found' };
      }
      
      // Complex validation rules that don't include ownership
      if (document.isSystem) {
        return { isValid: false, error: 'System documents cannot be deleted' };
      }
      
      if (document.hasActiveShares && document.shareCount > 0) {
        return { isValid: false, error: 'Document has active shares' };
      }
      
      // Looks comprehensive but missing the key authorization check
      return { isValid: true };
      
    } catch (error) {
      return { isValid: false, error: 'Validation failed' };
    }
  }
  
  // VULNERABLE: Document deletion without ownership verification
  async deleteDocument(docId: string) {
    try {
      // Multi-step deletion process
      await this.cleanupDocumentRelations(docId);
      await this.archiveDocumentData(docId);
      
      // SINK: Final deletion without ownership check
      const deletedDoc = await prisma.document.delete({
        where: { id: docId }
      });
      
      return deletedDoc;
      
    } catch (error) {
      throw new Error('Document deletion failed');
    }
  }
  
  private async cleanupDocumentRelations(docId: string) {
    // Clean up related records
    await prisma.documentShare.deleteMany({ where: { documentId: docId } });
    await prisma.documentComment.deleteMany({ where: { documentId: docId } });
    await prisma.documentVersion.deleteMany({ where: { documentId: docId } });
  }
  
  private async archiveDocumentData(docId: string) {
    // Archive document data before deletion
    const document = await prisma.document.findUnique({ where: { id: docId } });
    
    if (document) {
      await prisma.documentArchive.create({
        data: {
          originalId: document.id,
          title: document.title,
          content: document.content,
          archivedAt: new Date()
        }
      });
    }
  }
}