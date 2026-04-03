import type { Metadata } from "next";
import { Poppins } from "next/font/google";
import "./globals.css";

const poppins = Poppins({
  weight: ["300", "400", "500", "600", "700", "800", "900"],
  subsets: ["latin"],
  variable: "--font-poppins",
});

export const metadata: Metadata = {
  title: "SentinelAI Fusion | Phishing Detection Platform",
  description: "AI-powered phishing detection. Detect, analyze and respond to email threats in real time.",
};

// Inline script: read saved theme before first paint to prevent flash
const themeScript = `
(function(){
  try {
    var t = localStorage.getItem('sentinel-theme') || 'dark';
    document.documentElement.classList.add(t);
  } catch(e) {
    document.documentElement.classList.add('dark');
  }
})();
`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={poppins.variable} suppressHydrationWarning>
      <head>
        {/* eslint-disable-next-line @next/next/no-before-interactive-script-outside-document */}
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body className="min-h-screen w-full selection:bg-blue-500/20 selection:text-blue-300 font-sans antialiased overflow-x-hidden">
        {children}
      </body>
    </html>
  );
}
