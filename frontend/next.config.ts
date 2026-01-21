import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactCompiler: true,
  
  // Standalone output for Docker
  output: 'standalone',
  
  // Allowed dev origins for HTTPS
  allowedDevOrigins: [
    'https://192.168.200.115',
    'https://192.168.200.133',
    'https://localhost:3000',
    'https://localhost',
    'https://127.0.0.1:3000',
    'https://127.0.0.1',
  ],
  
  // Security headers
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-DNS-Prefetch-Control',
            value: 'on'
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY'
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin'
          },
        ],
      },
    ];
  },
};

export default nextConfig;
