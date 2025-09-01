import { ReactNode } from 'react';

// Basic layout for the test application
export default function RootLayout({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <title>SAST Validation Suite</title>
        <meta name="description" content="Security testing framework for SAST validation" />
      </head>
      <body>
        <header style={{ padding: '1rem', backgroundColor: '#f0f0f0', marginBottom: '2rem' }}>
          <h1>🔒 SAST Validation Suite</h1>
          <p><strong>⚠️ WARNING:</strong> This application contains intentionally vulnerable code for security testing purposes only.</p>
        </header>
        <main style={{ padding: '1rem' }}>
          {children}
        </main>
      </body>
    </html>
  );
}