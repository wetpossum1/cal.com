import { NextRequest, NextResponse } from 'next/server';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// A04: INSECURE DESIGN - Easy Level
// VULNERABLE: Race condition in financial transfer
// SAST should detect: Race condition vulnerability in critical business logic
export async function POST(request: NextRequest) {
  try {
    const { fromAccountId, toAccountId, amount } = await request.json();
    
    if (!fromAccountId || !toAccountId || !amount || amount <= 0) {
      return NextResponse.json({ error: 'Invalid transfer parameters' }, { status: 400 });
    }
    
    // VULNERABLE: Time-of-check-time-of-use (TOCTOU) race condition
    const fromAccount = await prisma.account.findUnique({
      where: { id: fromAccountId }
    });
    
    if (!fromAccount) {
      return NextResponse.json({ error: 'Source account not found' }, { status: 404 });
    }
    
    // VULNERABLE: Balance check separate from update - race condition window
    if (fromAccount.balance < amount) {
      return NextResponse.json({ error: 'Insufficient funds' }, { status: 400 });
    }
    
    // VULNERABLE: Multiple separate database operations allow race conditions
    // Between this check and the update, another transaction could modify the balance
    
    // Deduct from source account
    await prisma.account.update({
      where: { id: fromAccountId },
      data: { balance: fromAccount.balance - amount }
    });
    
    // Get destination account balance
    const toAccount = await prisma.account.findUnique({
      where: { id: toAccountId }
    });
    
    if (!toAccount) {
      // VULNERABLE: Already deducted from source, now destination is invalid
      // Partial transaction state - money could be lost
      return NextResponse.json({ error: 'Destination account not found' }, { status: 404 });
    }
    
    // Add to destination account
    await prisma.account.update({
      where: { id: toAccountId },
      data: { balance: toAccount.balance + amount }
    });
    
    // Create transaction record
    await prisma.transaction.create({
      data: {
        fromAccountId,
        toAccountId,
        amount,
        timestamp: new Date()
      }
    });
    
    return NextResponse.json({ 
      message: 'Transfer completed successfully',
      transactionId: Date.now().toString() // VULNERABLE: Predictable transaction ID
    });
    
  } catch (error) {
    return NextResponse.json(
      { error: 'Transfer failed' }, 
      { status: 500 }
    );
  }
}