// A09: SECURITY LOGGING AND MONITORING FAILURES - Medium Level
// VULNERABLE: Log injection and inadequate monitoring
// SAST should detect: User input in logs, monitoring bypass patterns

export class AuditService {
  
  // VULNERABLE: Log injection vulnerability
  logUserAction(action: string, username: string, details?: string) {
    // VULNERABLE: Direct user input in log messages
    console.log(`User action: ${action} by ${username}`);
    
    if (details) {
      // VULNERABLE: Unsanitized details can contain log injection
      console.log(`Action details: ${details}`);
    }
    
    // VULNERABLE: No structured logging
    // VULNERABLE: No log level classification
    // VULNERABLE: No correlation IDs
  }
  
  // VULNERABLE: Security event logging with injection
  logSecurityEvent(eventType: string, userId: string, metadata: any) {
    try {
      const timestamp = new Date().toISOString();
      
      // VULNERABLE: Metadata directly logged without sanitization
      const logMessage = `SECURITY EVENT: ${eventType} - User: ${userId} - Data: ${JSON.stringify(metadata)}`;
      
      console.log(logMessage);
      
      // VULNERABLE: No alerting mechanism for critical events
      // VULNERABLE: No rate limiting on security events
      
    } catch (error) {
      // VULNERABLE: Logging errors not handled properly
      console.log(`Failed to log security event: ${error.message}`);
    }
  }
  
  // VULNERABLE: Audit trail with tampering potential  
  async createAuditRecord(action: string, userId: string, resourceId: string, oldValue?: any, newValue?: any) {
    try {
      const auditRecord = {
        id: this.generateAuditId(), // VULNERABLE: Predictable audit IDs
        timestamp: Date.now(),
        action: action,
        userId: userId,
        resourceId: resourceId,
        oldValue: oldValue,
        newValue: newValue,
        // VULNERABLE: No integrity protection (hash, signature)
        // VULNERABLE: No tamper detection
      };
      
      // VULNERABLE: Audit logs stored without protection
      await this.storeAuditRecord(auditRecord);
      
      // VULNERABLE: No backup or redundant logging
      
    } catch (error) {
      // VULNERABLE: Audit failures not properly handled
      console.log(`Audit logging failed: ${error.message}`);
    }
  }
  
  // VULNERABLE: Predictable audit ID generation
  private generateAuditId(): string {
    // VULNERABLE: Timestamp-based IDs are predictable
    return `audit_${Date.now()}_${Math.floor(Math.random() * 1000)}`;
  }
  
  // VULNERABLE: Audit storage without integrity checks
  private async storeAuditRecord(record: any) {
    // Simplified storage - in real implementation would use database
    console.log(`AUDIT: ${JSON.stringify(record)}`);
  }
  
  // VULNERABLE: Log sanitization that can be bypassed
  logAdminAction(adminId: string, action: string, target: string, userInput: string) {
    try {
      // VULNERABLE: Incomplete log sanitization
      const sanitizedInput = this.sanitizeForLogs(userInput);
      
      // VULNERABLE: Admin actions logged but not properly monitored
      const logEntry = `ADMIN ACTION: ${action} by ${adminId} on ${target} - Input: ${sanitizedInput}`;
      
      console.log(logEntry);
      
      // VULNERABLE: No real-time monitoring or alerting
      // VULNERABLE: No anomaly detection
      
    } catch (error) {
      // VULNERABLE: Error handling exposes system details
      console.log(`Admin action logging failed: ${error.message} - Stack: ${error.stack}`);
    }
  }
  
  // VULNERABLE: Insufficient log sanitization
  private sanitizeForLogs(input: string): string {
    // VULNERABLE: Only basic sanitization, can be bypassed
    return input
      .replace(/\n/g, '\\n') // Only handles newlines
      .replace(/\r/g, '\\r') // Only handles carriage returns
      // Missing: \t, \x00, and other log injection vectors
      .substring(0, 1000); // Truncation without proper handling
  }
  
  // VULNERABLE: Monitoring with bypass conditions
  async monitorSuspiciousActivity(userId: string, activityType: string, metadata: any) {
    try {
      // Complex monitoring logic that can be bypassed
      const shouldMonitor = await this.shouldMonitorActivity(activityType, metadata);
      
      if (shouldMonitor) {
        this.logSecurityEvent(activityType, userId, metadata);
      }
      
      // VULNERABLE: Monitoring can be silently bypassed
      
    } catch (error) {
      // VULNERABLE: Monitoring failures not escalated
      console.log(`Activity monitoring failed: ${error.message}`);
    }
  }
  
  private async shouldMonitorActivity(activityType: string, metadata: any): Promise<boolean> {
    // VULNERABLE: Complex logic that might return false for malicious activities
    
    if (metadata.skipMonitoring === true) {
      // VULNERABLE: User can disable monitoring
      return false;
    }
    
    if (activityType === 'login' && metadata.source === 'internal') {
      // VULNERABLE: Internal activities not monitored
      return false;
    }
    
    // VULNERABLE: Default to not monitoring
    return false;
  }
  
  // VULNERABLE: Log viewing without access control
  async getAuditLogs(startDate: Date, endDate: Date, filters?: any) {
    try {
      // VULNERABLE: No access control on audit log viewing
      // VULNERABLE: Filters might contain injection
      
      const logs = await this.retrieveLogs(startDate, endDate, filters);
      
      // VULNERABLE: Returns sensitive audit data without filtering
      return logs;
      
    } catch (error) {
      throw new Error('Failed to retrieve audit logs');
    }
  }
  
  private async retrieveLogs(startDate: Date, endDate: Date, filters?: any) {
    // Simplified log retrieval
    return [
      {
        id: 'audit_001',
        action: 'login',
        userId: 'user123',
        timestamp: Date.now(),
        details: 'User login successful'
      }
    ];
  }
}