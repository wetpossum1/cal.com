# SAST Validation Suite for Cal.com

## ⚠️ Security Testing Framework - For Testing Purposes Only

**WARNING: This directory contains intentionally vulnerable code patterns for SAST tool validation only.**
**Use exclusively in isolated, controlled testing environments.**

## Purpose

This framework provides standardized vulnerable code patterns for validating Static Application Security Testing (SAST) tools against the Cal.com codebase. All code examples are designed for defensive security testing to improve detection capabilities.

## Critical Requirements

1. **Realism**: Uses actual production patterns - developers don't write obvious vulnerabilities
2. **Completeness**: Each vulnerability is exploitable to validate scanner accuracy
3. **Framework Integration**: Built using actual Cal.com/Next.js patterns and libraries

## Directory Structure

```
/sast-validation-suite/
├── /src/
│   ├── /controllers/     # API route handlers (Next.js App Router)
│   ├── /services/        # Business logic  
│   ├── /models/          # Data models and database interactions
│   ├── /utils/           # Helper functions
│   └── app.ts            # Main application setup
├── /tests/
│   └── EXPECTED_FINDINGS.md   # What scanner should detect
├── package.json          # Dependencies (including vulnerable versions)
└── README.md            # This file
```

## OWASP Top 10 Coverage

This test suite implements all OWASP Top 10 vulnerability categories:

- **A01**: Broken Access Control (3 complexity levels)
- **A02**: Cryptographic Failures (3 complexity levels)
- **A03**: Injection (3 complexity levels)
- **A04**: Insecure Design (3 complexity levels)
- **A05**: Security Misconfiguration (3 complexity levels)
- **A06**: Vulnerable and Outdated Components (3 complexity levels)
- **A07**: Identification and Authentication Failures (3 complexity levels)
- **A08**: Software and Data Integrity Failures (3 complexity levels)
- **A09**: Security Logging and Monitoring Failures (3 complexity levels)
- **A10**: Server-Side Request Forgery (3 complexity levels)

Each category includes:
- **Easy**: Direct vulnerability (1-2 function calls)
- **Medium**: Indirect vulnerability (2-3 layers of indirection)  
- **Hard**: Complex vulnerability (3+ layers, multiple files)
- **Safe**: Secure reference implementation

## Test Environment Setup

1. **Isolated Environment**: Use Docker container, VM, or dedicated test machine
2. **No Production Access**: No connection to production systems
3. **Clear Data Separation**: Separate from real applications
4. **Proper Authorization**: Ensure organizational approval for security testing

## Running the Test Suite

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Run type checking
npm run type-check

# Run linting
npm run lint
```

## Validation Checklist

### For each vulnerability:
- [ ] Confirm the vulnerability is exploitable
- [ ] Verify correct CWE is identifiable
- [ ] Check that taint flow is properly trackable
- [ ] Validate sink identification accuracy
- [ ] Ensure safe variants don't trigger false positives

### Coverage verification:
- [ ] All OWASP Top 10 categories implemented
- [ ] Three complexity levels per category
- [ ] Secure reference implementations included
- [ ] Framework-specific patterns are realistic
- [ ] Multi-file vulnerabilities test cross-module analysis

## Security Notes

- All vulnerable patterns mirror realistic production code
- No synthetic/obvious security anti-patterns
- Uses actual Cal.com dependencies and patterns
- Includes incomplete sanitization scenarios
- Tests validation bypass conditions

## Expected SAST Scanner Output

See `/tests/EXPECTED_FINDINGS.md` for detailed information about what findings each SAST tool should detect when scanning this test suite.

---

**Remember**: This is for defensive security testing only. Never deploy to production environments.