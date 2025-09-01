export default function HomePage() {
  return (
    <div>
      <h2>SAST Scanner Validation Test Suite</h2>
      
      <div style={{ backgroundColor: '#ffebee', padding: '1rem', marginBottom: '2rem', borderRadius: '4px' }}>
        <h3>⚠️ Security Warning</h3>
        <p>This application contains <strong>intentionally vulnerable code</strong> designed to test Static Application Security Testing (SAST) tools.</p>
        <ul>
          <li>Do not deploy to production environments</li>
          <li>Use only in isolated testing environments</li>
          <li>All vulnerabilities are designed for defensive security testing</li>
        </ul>
      </div>
      
      <h3>Test Categories Implemented</h3>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
        
        <div style={{ border: '1px solid #ddd', padding: '1rem', borderRadius: '4px' }}>
          <h4>A01: Broken Access Control</h4>
          <p>✅ Easy: Direct authorization bypass</p>
          <p>✅ Medium: IDOR through service layer</p> 
          <p>✅ Hard: Complex delegation bypass</p>
          <code>/api/admin/users/[id]</code>
        </div>
        
        <div style={{ border: '1px solid #ddd', padding: '1rem', borderRadius: '4px' }}>
          <h4>A02: Cryptographic Failures</h4>
          <p>✅ Easy: Hardcoded secrets</p>
          <p>✅ Medium: Weak algorithms (MD5/SHA1)</p>
          <p>✅ Hard: Complex crypto implementation</p>
          <code>/api/encrypt</code>
        </div>
        
        <div style={{ border: '1px solid #ddd', padding: '1rem', borderRadius: '4px' }}>
          <h4>A03: Injection</h4>
          <p>✅ Easy: SQL injection</p>
          <p>✅ Medium: NoSQL injection</p>
          <p>✅ Hard: LDAP injection</p>
          <code>/api/users/[id]</code>
        </div>
        
        <div style={{ border: '1px solid #ddd', padding: '1rem', borderRadius: '4px' }}>
          <h4>A04: Insecure Design</h4>
          <p>✅ Easy: Race condition</p>
          <p>🚧 Medium: Rate limiting flaws</p>
          <p>🚧 Hard: State management issues</p>
          <code>/api/transfer</code>
        </div>
        
        <div style={{ border: '1px solid #ddd', padding: '1rem', borderRadius: '4px' }}>
          <h4>A05: Security Misconfiguration</h4>
          <p>✅ Easy: Debug mode enabled</p>
          <p>✅ Medium: Verbose errors</p>
          <p>✅ Hard: CORS misconfiguration</p>
          <code>/api/debug</code>
        </div>
        
        <div style={{ border: '1px solid #ddd', padding: '1rem', borderRadius: '4px' }}>
          <h4>A06: Vulnerable Components</h4>
          <p>✅ Easy: Known vulnerable deps</p>
          <p>✅ Medium: Transitive vulnerabilities</p>
          <p>✅ Hard: Dynamic loading</p>
          <code>/api/plugin/[name]</code>
        </div>
        
        <div style={{ border: '1px solid #ddd', padding: '1rem', borderRadius: '4px' }}>
          <h4>A07: Authentication Failures</h4>
          <p>✅ Easy: Weak password policy</p>
          <p>✅ Medium: Session fixation</p>
          <p>✅ Hard: JWT implementation flaws</p>
          <code>/api/auth/register</code>
        </div>
        
        <div style={{ border: '1px solid #ddd', padding: '1rem', borderRadius: '4px' }}>
          <h4>A08: Integrity Failures</h4>
          <p>✅ Easy: Insecure deserialization</p>
          <p>✅ Medium: Unsigned code execution</p>
          <p>✅ Hard: CI/CD vulnerabilities</p>
          <code>/api/data/load</code>
        </div>
        
        <div style={{ border: '1px solid #ddd', padding: '1rem', borderRadius: '4px' }}>
          <h4>A09: Logging Failures</h4>
          <p>✅ Easy: Missing security logging</p>
          <p>✅ Medium: Log injection</p>
          <p>✅ Hard: Monitoring bypass</p>
          <code>/api/auth/signin</code>
        </div>
        
        <div style={{ border: '1px solid #ddd', padding: '1rem', borderRadius: '4px' }}>
          <h4>A10: SSRF</h4>
          <p>✅ Easy: Direct URL fetch</p>
          <p>🚧 Medium: Image processing SSRF</p>
          <p>🚧 Hard: Complex validation bypass</p>
          <code>/api/fetch</code>
        </div>
        
      </div>
      
      <div style={{ marginTop: '2rem', padding: '1rem', backgroundColor: '#e8f5e8', borderRadius: '4px' }}>
        <h3>📖 Documentation</h3>
        <ul>
          <li><code>README.md</code> - Complete implementation guide</li>
          <li><code>tests/EXPECTED_FINDINGS.md</code> - What SAST tools should detect</li>
          <li><code>package.json</code> - Includes vulnerable dependencies for testing</li>
        </ul>
      </div>
      
      <div style={{ marginTop: '2rem', padding: '1rem', backgroundColor: '#fff3cd', borderRadius: '4px' }}>
        <h3>🔧 Usage</h3>
        <ol>
          <li>Run your SAST scanner against this codebase</li>
          <li>Compare findings with <code>tests/EXPECTED_FINDINGS.md</code></li>
          <li>Verify taint flow tracking for complex vulnerabilities</li>
          <li>Check false positive rate on safe implementations</li>
        </ol>
      </div>
      
    </div>
  );
}