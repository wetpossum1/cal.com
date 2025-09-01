/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    appDir: true,
  },
  eslint: {
    ignoreDuringBuilds: true, // Allow vulnerable patterns during build
  },
  typescript: {
    ignoreBuildErrors: true, // Allow intentional vulnerabilities to build
  },
  env: {
    // Intentionally vulnerable configuration for testing
    DEBUG_MODE: 'true',
    VERBOSE_ERRORS: 'true',
    DISABLE_SECURITY_HEADERS: 'true'
  },
  // Intentionally weak security headers for testing
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'ALLOWALL'
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          }
        ],
      },
    ]
  }
}

module.exports = nextConfig