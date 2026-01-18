import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  reactCompiler: true,
  allowedDevOrigins: [
    'http://192.168.200.115',
    'http://192.168.200.133',
    'http://localhost:3000',
    'http://localhost',
    'http://127.0.0.1:3000',
    'http://127.0.0.1',
  ],
};

export default nextConfig;
