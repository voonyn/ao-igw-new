import type { Metadata } from "next"
import { Inter } from "next/font/google"
import "./globals.css"

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
})

export const metadata: Metadata = {
  title: "AlphaOmega — Sign In",
  description: "Sign in to your organization’s AlphaOmega portal.",
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" className={`${inter.variable} antialiased`}>
      <body className="relative flex min-h-screen items-center justify-center px-4 py-8 font-sans max-[520px]:items-stretch max-[520px]:p-0">
        {children}
      </body>
    </html>
  )
}
