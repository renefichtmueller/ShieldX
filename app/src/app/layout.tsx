'use client'

import './globals.css'
import Link from 'next/link'
import { usePathname } from 'next/navigation'

const NAV_ITEMS = [
  { href: '/', label: 'Overview', icon: '\u25C8' },
  { href: '/kill-chain', label: 'Kill Chain', icon: '\u26D3' },
  { href: '/incidents', label: 'Incidents', icon: '\u26A0' },
  { href: '/learning', label: 'Learning', icon: '\u2699' },
  { href: '/compliance', label: 'Compliance', icon: '\u2611' },
  { href: '/healing', label: 'Healing', icon: '\u2695' },
  { href: '/resistance', label: 'Resistance', icon: '\u2694' },
  { href: '/config', label: 'Config', icon: '\u2630' },
  { href: '/try-it', label: 'Try It', icon: '\u25B6' },
] as const

export default function RootLayout({
  children,
}: {
  readonly children: React.ReactNode
}) {
  const pathname = usePathname()

  return (
    <html lang="en">
      <head>
        <title>ShieldX Dashboard</title>
        <meta name="description" content="ShieldX LLM Prompt Injection Defense Dashboard" />
      </head>
      <body>
        <div className="app-layout">
          <aside className="sidebar">
            <div className="sidebar-logo">
              <span className="logo-icon">{'\u25C6'}</span>
              ShieldX
            </div>
            <nav className="sidebar-nav">
              {NAV_ITEMS.map((item) => {
                const isActive =
                  item.href === '/'
                    ? pathname === '/'
                    : pathname.startsWith(item.href)
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`sidebar-link ${isActive ? 'active' : ''}`}
                  >
                    <span className="link-icon">{item.icon}</span>
                    {item.label}
                  </Link>
                )
              })}
            </nav>
            <div className="sidebar-footer">
              ShieldX v0.1.0 &middot; Defense Active
            </div>
          </aside>
          <main className="main-content">
            {children}
          </main>
        </div>
      </body>
    </html>
  )
}
