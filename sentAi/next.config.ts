import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Required to silence Turbopack/webpack config conflict in Next.js 16
  turbopack: {},
  allowedDevOrigins: ["sentinel4me.duckdns.org", "localhost:3002", "localhost:3000"],
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001"}/api/:path*`,
      },
      {
        source: "/screenshots/:path*",
        destination: `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001"}/screenshots/:path*`,
      },
    ]
  },
  // Allow images from any domain (for Apify screenshots)
  images: {
    remotePatterns: [
      { protocol: "https", hostname: "**" },
      { protocol: "http", hostname: "localhost" },
    ],
  },
};

export default nextConfig;
