import { NextRequest, NextResponse } from 'next/server';
import { DocumentService } from '@/services/documentService';
import { getServerSession } from 'next-auth/next';

// A01: BROKEN ACCESS CONTROL - Hard Level
// VULNERABLE: Complex authorization bypass through delegation layers
// SAST should detect: Multi-layer taint flow where authorization is lost between layers
export async function GET(
  request: NextRequest,
  { params }: { params: { docId: string } }
) {
  try {
    const session = await getServerSession();
    const docId = params.docId; // TAINT SOURCE: user input from URL parameter
    
    // Basic session check (looks secure but isn't sufficient)
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    const documentService = new DocumentService();
    
    // VULNERABLE: Delegates to service without passing user context
    // The service layer won't be able to verify document access permissions
    const document = await documentService.fetchDocument(docId);
    
    if (!document) {
      return NextResponse.json({ error: 'Document not found' }, { status: 404 });
    }
    
    // Returns potentially unauthorized document
    return NextResponse.json(document);
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Internal server error' }, 
      { status: 500 }
    );
  }
}

// VULNERABLE: Document sharing with complex authorization bypass
export async function POST(
  request: NextRequest,
  { params }: { params: { docId: string } }
) {
  try {
    const session = await getServerSession();
    const docId = params.docId; // TAINT SOURCE
    const { shareWith, permissions } = await request.json();
    
    // Session check that looks secure
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    // VULNERABLE: Share document without verifying if user owns it
    const documentService = new DocumentService();
    const shareResult = await documentService.shareDocument(docId, shareWith, permissions);
    
    return NextResponse.json(shareResult);
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to share document' }, 
      { status: 500 }
    );
  }
}

// VULNERABLE: Complex deletion flow with authorization bypass
export async function DELETE(
  request: NextRequest,
  { params }: { params: { docId: string } }
) {
  try {
    const session = await getServerSession();
    const docId = params.docId; // TAINT SOURCE
    
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    const documentService = new DocumentService();
    
    // Complex multi-step deletion that obscures authorization issue
    const validationResult = await documentService.validateDocumentForDeletion(docId);
    
    if (!validationResult.isValid) {
      return NextResponse.json({ error: validationResult.error }, { status: 400 });
    }
    
    // VULNERABLE: Proceeds with deletion without checking ownership
    const deleteResult = await documentService.deleteDocument(docId);
    
    return NextResponse.json({ 
      message: 'Document deleted successfully',
      deletedId: deleteResult.id
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to delete document' }, 
      { status: 500 }
    );
  }
}