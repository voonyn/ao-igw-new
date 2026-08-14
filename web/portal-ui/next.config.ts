import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Emit .next/standalone (server.js + only the traced node_modules) so the
  // container image ships a self-contained server instead of the full
  // dependency tree behind `next start`. No effect on `pnpm dev`.
  output: "standalone",
  allowedDevOrigins: ['dev-portal.alpha-omega.io'],
};

export default nextConfig;
