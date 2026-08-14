import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

// One family. Space Grotesk and IBM Plex Sans were reachable only through the
// `[data-font]` selectors, which nothing ever set — two webfonts downloaded to
// serve a switch that did not exist.
const inter = Inter({ subsets: ["latin"], variable: "--font-inter", weight: ["400", "500", "600", "700"] });

export const metadata: Metadata = {
  title: "AlphaOmega — Admin Console",
  description: "Identity & Access Management admin console for the AlphaOmega platform.",
};

// Apply the persisted theme before paint to avoid a flash of the wrong mode.
const themeScript = `(function(){try{var t=localStorage.getItem('ao-console-theme');if(t==='dark'||t==='light'){document.documentElement.setAttribute('data-theme',t);}}catch(e){}})();`;

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={inter.variable}
      suppressHydrationWarning
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
