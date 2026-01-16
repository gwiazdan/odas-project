import Link from "next/link";
import Image from "next/image";

export default function AuthLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return(
    <section className="bg-neutral-950 min-h-screen">
      <div className="flex flex-col items-center justify-center px-6 py-8 mx-auto md:h-screen lg:py-0">
        {/* Logo */}
        <Link href="/" className="flex items-center mb-6 text-2xl font-semibold text-white gap-3">
          <Image src="/mailbox.svg" alt="Logo" width={32} height={32} />
          <span>SafeMessage</span>
        </Link>
        {children}
      </div>
    </section>
  )
}
