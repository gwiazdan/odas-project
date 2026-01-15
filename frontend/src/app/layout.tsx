'use client';
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";
import Image from "next/image";
import "./globals.css";
import { usePathname } from "next/navigation";
import { useState } from "react";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const pathname = usePathname();
  const isAuth = pathname.startsWith('/login') || pathname.startsWith('/signup');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  if (isAuth) return <html lang="en"><body className={`${geistSans.variable} ${geistMono.variable}`}>{children}</body></html>;

  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable} antialiased bg-white`}>
        <div className="flex flex-col h-screen">
          {/* Navbar */}
          <nav className="bg-white border-b border-gray-800 px-4 py-2.5 fixed left-0 right-0 top-0 z-50 bg-background">
            <div className="flex flex-wrap justify-between items-center">
              <div className="flex justify-start items-center">
                <button
                  onClick={() => setSidebarOpen(!sidebarOpen)}
                  className="p-2 mr-2 text-gray-600 rounded-lg cursor-pointer md:hidden hover:text-gray-900 hover:bg-gray-100 focus:bg-gray-100 focus:ring-2 focus:ring-gray-100"
                >
                  <svg
                    aria-hidden="true"
                    className="w-6 h-6"
                    fill="currentColor"
                    viewBox="0 0 20 20"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path
                      fillRule="evenodd"
                      d="M3 5a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zM3 10a1 1 0 011-1h6a1 1 0 110 2H4a1 1 0 01-1-1zM3 15a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z"
                      clipRule="evenodd"
                    ></path>
                  </svg>
                </button>
                <Link href="/inbox" className="flex items-center gap-2 mr-4">
                  <Image src="/mailbox.svg" alt="Logo" width={32} height={32} />
                  <span className="self-center text-2xl font-semibold whitespace-nowrap">SafeMessage</span>
                </Link>
              </div>
              <div className="flex items-center lg:order-2">
                <button
                  type="button"
                  className="flex mx-3 text-sm bg-gray-800 rounded-full md:mr-0 focus:ring-4 focus:ring-gray-300"
                  onClick={() => {
                    fetch('/api/auth/logout', { method: 'POST' });
                    window.location.href = '/login';
                  }}
                >
                  <span className="sr-only">User menu</span>
                  <div className="w-8 h-8 rounded-full bg-gray-700 flex items-center justify-center text-white text-xs font-semibold">U</div>
                </button>
              </div>
            </div>
          </nav>

          {/* Sidebar */}
          <aside
            className={`fixed top-0 left-0 z-40 w-64 h-screen pt-14 transition-transform ${
              sidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
            } border-r border-gray-800 md:translate-x-0`}
            aria-label="Sidenav"
          >
            <div className="overflow-y-auto py-5 px-3 h-full bg-neutral flex flex-col">
              <button
                type="button"
                className="w-full text-black bg-white hover:bg-gray-200 focus:ring-4 focus:ring-blue-300 font-medium rounded-lg text-sm px-5 py-2.5 mb-6 cursor-pointer"
              >
                + New Message
              </button>

              <ul className="space-y-2 flex-1">
                <li>
                  <Link
                    href="/inbox"
                    className="flex items-center p-2 text-base tracking-wider font-bold text-white rounded-lg hover:text-black hover:bg-white group transition duration-300 ease-in"
                  >
                    <svg className="w-7 h-7" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                      <path fillRule="evenodd" clipRule="evenodd" d="M6.205 3h11.59c1.114 0 1.519.116 1.926.334.407.218.727.538.945.945.218.407.334.811.334 1.926v11.59c0 1.114-.116 1.519-.334 1.926a2.272 2.272 0 0 1-.945.945c-.407.218-.811.334-1.926.334H6.205c-1.115 0-1.519-.116-1.926-.334a2.272 2.272 0 0 1-.945-.945C3.116 19.314 3 18.91 3 17.795V6.205c0-1.115.116-1.519.334-1.926.218-.407.538-.727.945-.945C4.686 3.116 5.09 3 6.205 3zm0 2c-.427 0-.694.019-.849.049a.353.353 0 0 0-.134.049.275.275 0 0 0-.124.124.353.353 0 0 0-.049.134c-.03.155-.049.422-.049.849V15h3.413c.321 0 .607.205.754.49.375.728 1.258 2.01 2.833 2.01 1.575 0 2.458-1.282 2.833-2.01.147-.285.433-.49.754-.49H19V6.205c0-.427-.019-.694-.049-.849a.353.353 0 0 0-.049-.134.275.275 0 0 0-.124-.124.353.353 0 0 0-.134-.049c-.155-.03-.422-.049-.849-.049H6.205z" fill="currentColor"/>
                    </svg>
                    <span className="ml-3">Inbox</span>
                  </Link>
                </li>
                <li>
                  <Link
                    href="/sent"
                    className="flex items-center p-2 text-base tracking-wider font-bold text-white rounded-lg hover:text-black hover:bg-white group transition duration-300 ease-in"
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-7 h-7 " viewBox="0 0 32 32">
                      <path d="m19 31-6-12-12-6L31 1 19 31zm-6-12L25 7" data-name="12-sent" fill='currentColor'/>
                    </svg>
                    <span className="ml-3">Sent</span>
                  </Link>
                </li>
              </ul>
            </div>
          </aside>

          {/* Main Content */}
          <main className="p-4 md:ml-64 pt-20 flex-1 overflow-y-auto">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
