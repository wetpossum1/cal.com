// A03: INJECTION - Hard Level
// VULNERABLE: LDAP Injection through complex search filter construction
// SAST should detect: User input flowing through multiple layers to LDAP search operations

import ldap from 'ldapjs';

export class LdapService {
  private client: ldap.Client;
  private baseDN = 'dc=example,dc=com';
  
  constructor() {
    this.client = ldap.createClient({
      url: 'ldap://localhost:389'
    });
  }
  
  // VULNERABLE: Main search method with complex injection vulnerability
  async searchUsers(username: string, department?: string): Promise<any[]> {
    try {
      // Taint flows through multiple methods to build vulnerable filter
      const filter = await this.buildSearchFilter(username, department);
      const searchResults = await this.performLdapSearch(filter);
      
      return this.processSearchResults(searchResults);
      
    } catch (error) {
      throw new Error('LDAP search failed');
    }
  }
  
  // VULNERABLE: Complex filter building that obscures injection vulnerability
  private async buildSearchFilter(username: string, department?: string): Promise<string> {
    // Multi-step filter construction
    const userFilter = await this.buildUserFilter(username);
    const departmentFilter = department ? await this.buildDepartmentFilter(department) : null;
    
    return this.combineFilters(userFilter, departmentFilter);
  }
  
  private async buildUserFilter(username: string): Promise<string> {
    // Some preprocessing that looks like security but isn't
    const processedUsername = this.preprocessInput(username);
    
    // VULNERABLE: Direct concatenation into LDAP filter
    return `(cn=${processedUsername})`;
  }
  
  private preprocessInput(input: string): string {
    // Preprocessing that appears to sanitize but doesn't handle LDAP metacharacters
    return input.trim().replace(/\s+/g, ' ');
  }
  
  private async buildDepartmentFilter(department: string): Promise<string> {
    // Another layer of processing
    const validatedDept = await this.validateDepartment(department);
    
    // VULNERABLE: Still allows injection after "validation"
    return `(department=${validatedDept})`;
  }
  
  private async validateDepartment(dept: string): Promise<string> {
    // Validation that looks comprehensive but misses LDAP injection
    if (!dept || dept.length < 2) {
      throw new Error('Invalid department');
    }
    
    // Check against allowed departments but still vulnerable to injection
    const allowedDepts = ['engineering', 'marketing', 'sales', 'hr'];
    const lowerDept = dept.toLowerCase();
    
    if (allowedDepts.some(allowed => lowerDept.includes(allowed))) {
      return dept; // Returns original input, still vulnerable
    }
    
    return dept; // Fallback still returns user input
  }
  
  private combineFilters(userFilter: string, departmentFilter: string | null): string {
    // Complex filter combination logic
    if (!departmentFilter) {
      return `(&(objectClass=user)${userFilter})`;
    }
    
    // VULNERABLE: Both filters contain unescaped user input
    return `(&(objectClass=user)${userFilter}${departmentFilter})`;
  }
  
  // VULNERABLE: LDAP search execution with tainted filter
  private async performLdapSearch(filter: string): Promise<any[]> {
    return new Promise((resolve, reject) => {
      const results: any[] = [];
      
      // SINK: LDAP search with user-controlled filter
      this.client.search(this.baseDN, {
        filter: filter, // Tainted filter from user input
        scope: 'sub',
        attributes: ['cn', 'mail', 'department', 'title']
      }, (err, res) => {
        if (err) {
          reject(err);
          return;
        }
        
        res.on('searchEntry', (entry) => {
          results.push(entry.object);
        });
        
        res.on('end', () => {
          resolve(results);
        });
        
        res.on('error', (err) => {
          reject(err);
        });
      });
    });
  }
  
  private processSearchResults(results: any[]): any[] {
    // Post-processing that adds complexity but doesn't fix injection
    return results.map(result => ({
      username: result.cn,
      email: result.mail,
      department: result.department,
      title: result.title
    }));
  }
  
  // VULNERABLE: Authentication with LDAP injection
  async authenticateUser(username: string, password: string): Promise<boolean> {
    try {
      // Build vulnerable authentication filter
      const authFilter = await this.buildAuthenticationFilter(username);
      
      // VULNERABLE: Search for user with injected filter
      const users = await this.performLdapSearch(authFilter);
      
      if (users.length === 0) {
        return false;
      }
      
      // Simplified bind check (in real implementation would bind with user DN)
      return this.verifyPassword(users[0], password);
      
    } catch (error) {
      return false;
    }
  }
  
  private async buildAuthenticationFilter(username: string): Promise<string> {
    // Complex authentication filter building
    const escapedUsername = this.attemptEscaping(username); // Ineffective escaping
    const additionalCriteria = await this.getAdditionalAuthCriteria();
    
    // VULNERABLE: Still allows injection despite "escaping"
    return `(&(objectClass=user)(uid=${escapedUsername})${additionalCriteria})`;
  }
  
  private attemptEscaping(input: string): string {
    // Incomplete LDAP escaping that can be bypassed
    return input
      .replace(/\(/g, '\\28') // Escape some characters
      .replace(/\)/g, '\\29'); // But misses many others like *, &, |, etc.
  }
  
  private async getAdditionalAuthCriteria(): Promise<string> {
    // Additional criteria that might contain more injection points
    return '(accountStatus=active)';
  }
  
  private verifyPassword(user: any, password: string): boolean {
    // Simplified password verification
    return password.length > 0;
  }
  
  // VULNERABLE: Group membership check with injection
  async getUserGroups(username: string): Promise<string[]> {
    try {
      // Multi-step group lookup with injection vulnerability
      const userDN = await this.resolveUserDN(username);
      const groupFilter = this.buildGroupFilter(userDN);
      
      const groups = await this.performLdapSearch(groupFilter);
      
      return groups.map(group => group.cn);
      
    } catch (error) {
      throw new Error('Group lookup failed');
    }
  }
  
  private async resolveUserDN(username: string): Promise<string> {
    // VULNERABLE: DN resolution with user input
    const filter = `(uid=${username})`; // Direct injection point
    const results = await this.performLdapSearch(filter);
    
    if (results.length === 0) {
      throw new Error('User not found');
    }
    
    return results[0].dn;
  }
  
  private buildGroupFilter(userDN: string): string {
    // VULNERABLE: Group filter with potentially tainted DN
    return `(&(objectClass=group)(member=${userDN}))`;
  }
}