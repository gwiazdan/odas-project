'use client';
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";
import Image from "next/image";
import "./globals.css";
import { usePathname } from "next/navigation";
import { useState, useEffect } from "react";
import { CryptoProvider, useCryptoContext } from "@/context/CryptoContext";
import { UserProvider, useUserContext } from "@/context/UserContext";
import { sanitizeInput } from "@/lib/security";
import ComposeMessage from "@/components/ComposeMessage";
import TwoFactorSetup from "@/components/TwoFactorSetup";

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
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable} antialiased`}>
      <body>
        <CryptoProvider>
          <UserProvider>
            <LayoutWrapper>{children}</LayoutWrapper>
          </UserProvider>
        </CryptoProvider>
      </body>
    </html>
  );
}

function LayoutWrapper({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isAuth = pathname.startsWith('/login') || pathname.startsWith('/signup');

  if (isAuth) {
    return children;
  }

  return <LayoutContent>{children}</LayoutContent>;
}

function LayoutContent({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isAuth = pathname.startsWith('/login') || pathname.startsWith('/signup');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [composeOpen, setComposeOpen] = useState(false);
  const [twoFactorSetupOpen, setTwoFactorSetupOpen] = useState(false);
  const { user, setUser } = useUserContext();
  const { privateKeyPEM } = useCryptoContext();

  useEffect(() => {
    // Only fetch user if not already in context (e.g., from login)
    if (user) {
      return;
    }

    // Fetch user data from session
    const fetchUser = async () => {
      try {
        const apiUrl = process.env.NEXT_PUBLIC_API_URL;
        if (!apiUrl) {
          console.error('NEXT_PUBLIC_API_URL is not configured');
          return;
        }

        const response = await fetch(`${apiUrl}/api/v1/auth/me`, {
          credentials: 'include',
        });

        if (response.ok) {
          const data = await response.json();
          setUser(data);
        } else if (response.status === 401 || response.status === 403) {
          // Not authenticated, which is expected on public pages
          console.log('User not authenticated');
        } else {
          console.error('Failed to fetch user:', response.status, response.statusText);
        }
      } catch (err) {
        console.error('Failed to fetch user:', err);
        // Network error or CORS issue - don't crash the app
      }
    };

    // Only fetch if user not already in context
    fetchUser();
  }, [user, setUser]);

  return (
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
                  className="flex mx-3 text-sm rounded-full md:mr-0 relative cursor-pointer"
                  onClick={() => setUserMenuOpen(!userMenuOpen)}
                >
                  <span className="sr-only">User menu</span>
                  <div className="w-8 h-8 rounded-full flex items-center justify-center text-white text-xs font-semibold bg-neutral-900">
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-6 h-6" viewBox="0 0 32 32">
                      <circle cx="16" cy="8" r="7" fill="currentColor"/>
                      <path d="M28 31a12 12 0 0 0-24 0Z" fill="currentColor"/>
                    </svg>
                  </div>

                  {/* Dropdown Menu */}
                  {userMenuOpen && (
                    <div className="absolute right-0 top-full mt-2 w-48 bg-background rounded-lg shadow-lg border border-gray-700 z-50">
                      <div className="px-4 py-2 border-b border-gray-700 flex gap-2">
                        <div className="w-8 h-8 rounded-full flex items-center justify-center text-white text-xs font-semibold bg-neutral-900">
                          <svg xmlns="http://www.w3.org/2000/svg" className="w-6 h-6" viewBox="0 0 32 32">
                            <circle cx="16" cy="8" r="7" fill="currentColor"/>
                            <path d="M28 31a12 12 0 0 0-24 0Z" fill="currentColor"/>
                          </svg>
                        </div>
                        <div className="flex flex-col text-start">
                          <p className="text-white text-sm font-semibold">{user ? `${sanitizeInput(user.first_name)} ${sanitizeInput(user.last_name)}` : 'User'}</p>
                          <p className="text-gray-400 text-xs">{user ? sanitizeInput(user.email) : 'Loading...'}</p>
                        </div>
                      </div>
                      <div
                        onClick={() => {
                          setUserMenuOpen(false);
                          setTwoFactorSetupOpen(true);
                        }}
                        className="flex w-full text-left px-4 py-2 hover:bg-neutral-800 transition cursor-pointer gap-2 border-b border-gray-700"
                        role="button"
                        tabIndex={0}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            (e.target as HTMLDivElement).click();
                          }
                        }}
                      >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                        </svg>
                        {user?.is_2fa_enabled ? 'Disable 2FA' : 'Enable 2FA'}
                      </div>
                      <div
                        onClick={async () => {
                          try {
                            await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/auth/logout`, {
                              method: 'POST',
                              credentials: 'include',
                            });
                          } catch (err) {
                            console.error('Logout failed:', err);
                          }
                          window.location.href = '/login';
                        }}
                        className="flex w-full text-left px-4 py-2 hover:bg-neutral-800 transition cursor-pointer gap-2 block"
                        role="button"
                        tabIndex={0}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            (e.target as HTMLDivElement).click();
                          }
                        }}
                      >
                        <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5" xmlns="http://www.w3.org/2000/svg">
                          <path d="M21 12L13 12" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                          <path d="M18 15L20.913 12.087V12.087C20.961 12.039 20.961 11.961 20.913 11.913V11.913L18 9" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                          <path d="M16 5V4.5V4.5C16 3.67157 15.3284 3 14.5 3H5C3.89543 3 3 3.89543 3 5V19C3 20.1046 3.89543 21 5 21H14.5C15.3284 21 16 20.3284 16 19.5V19.5V19" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        </svg>
                        Logout
                      </div>
                    </div>
                  )}
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
              {/* Compose Button */}
              {user && privateKeyPEM && (
                <button
                  onClick={() => setComposeOpen(true)}
                  className="w-full text-black bg-white hover:bg-gray-200 font-bold tracking-wide rounded-lg text-md px-5 py-2 mb-6 cursor-pointer">
                + New Message
                </button>
              )}
              <ul className="space-y-2 flex-1">
                <li>
                  <Link
                    href="/inbox"
                    className={`flex items-center p-2 text-base tracking-wider font-bold rounded-lg group transition duration-400 ease-in ${
                      pathname === '/inbox'
                        ? 'bg-neutral-700'
                        : 'hover:bg-neutral-700'
                    }`}
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
                    className={`flex items-center p-2 text-base tracking-wider font-bold rounded-lg group transition duration-300 ease-in ${
                      pathname === '/sent'
                        ? 'bg-neutral-700'
                        : 'hover:bg-neutral-700'
                    }`}
                  >
                    <svg className="w-7 h-7" viewBox="0 0 32 32">
                      <path fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="m19 31-6-12-12-6L31 1 19 31zm-6-12L25 7"/>
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

          {/* Global Compose Modal */}
          {composeOpen && (
            <ComposeMessage onClose={() => setComposeOpen(false)} />
          )}

          {/* 2FA Setup Modal */}
          {twoFactorSetupOpen && (
            <TwoFactorSetup
              onClose={() => setTwoFactorSetupOpen(false)}
              onSuccess={() => {
                // Refetch user to update 2FA status
                const fetchUser = async () => {
                  try {
                    const apiUrl = process.env.NEXT_PUBLIC_API_URL;
                    const response = await fetch(`${apiUrl}/api/v1/auth/me`, {
                      credentials: 'include',
                    });
                    if (response.ok) {
                      const data = await response.json();
                      setUser(data);
                    }
                  } catch (err) {
                    console.error('Failed to fetch user:', err);
                  }
                };
                fetchUser();
              }}
            />
          )}
        </div>
      );
    }
