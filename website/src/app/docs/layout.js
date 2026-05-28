"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { BookOpen, Layers, CheckCircle2, RefreshCw, Shield, Terminal, Sliders, Cpu } from "lucide-react";

export default function DocsLayout({ children }) {
  const pathname = usePathname();

  const menuItems = [
    {
      title: "Introduction",
      items: [
        { label: "Getting Started", href: "/docs", icon: BookOpen },
        { label: "Core Concepts", href: "/docs/core-concepts", icon: Cpu },
      ]
    },
    {
      title: "Workflow Engine",
      items: [
        { label: "Verification Workflow", href: "/docs/verification-workflow", icon: CheckCircle2 },
        { label: "Replay & Diff", href: "/docs/replay-diff", icon: RefreshCw },
        { label: "Canonical Findings", href: "/docs/canonical-findings", icon: Shield },
      ]
    },
    {
      title: "Reference",
      items: [
        { label: "Scanner Modules", href: "/docs/modules", icon: Sliders },
        { label: "CLI Interface", href: "/docs/cli", icon: Terminal },
        { label: "System Internals", href: "/docs/internals", icon: Layers },
      ]
    }
  ];

  const getTocLinks = (path) => {
    switch (path) {
      case "/docs":
        return [
          { label: "Overview", href: "#overview" },
          { label: "Introduction", href: "#introduction" },
          { label: "Installation", href: "#installation" },
          { label: "Usage Examples", href: "#examples" }
        ];
      case "/docs/core-concepts":
        return [
          { label: "Overview", href: "#overview" },
          { label: "State Evolution", href: "#state-evolution" },
          { label: "Event Bus", href: "#decoupled-bus" },
          { label: "Module Discovery", href: "#dynamic-discovery" }
        ];
      case "/docs/verification-workflow":
        return [
          { label: "Overview", href: "#overview" },
          { label: "Execution Stages", href: "#lifecycle" },
          { label: "Telemetry Details", href: "#implementation" }
        ];
      case "/docs/replay-diff":
        return [
          { label: "Overview", href: "#overview" },
          { label: "State Diff Engine", href: "#concept" },
          { label: "Trace Replays", href: "#replaying" }
        ];
      case "/docs/canonical-findings":
        return [
          { label: "Overview", href: "#overview" },
          { label: "Finding Schema", href: "#schema" },
          { label: "Specifications", href: "#fields" }
        ];
      case "/docs/modules":
        return [
          { label: "Overview", href: "#overview" },
          { label: "Module Domains", href: "#structure" }
        ];
      case "/docs/cli":
        return [
          { label: "Overview", href: "#overview" },
          { label: "CLI Arguments", href: "#options" }
        ];
      case "/docs/internals":
        return [
          { label: "Overview", href: "#overview" },
          { label: "Event Dispatcher", href: "#event-dispatching" },
          { label: "Telemetry & Logs", href: "#telemetry" }
        ];
      case "/docs/architecture":
        return [
          { label: "Overview", href: "#overview" },
          { label: "Pipeline Blueprints", href: "#blueprints" },
          { label: "System Flow", href: "#flow" }
        ];
      default:
        return [
          { label: "Overview", href: "#overview" }
        ];
    }
  };

  const handleTocClick = (e, href) => {
    e.preventDefault();
    const id = href.replace("#", "");
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      window.history.pushState(null, "", href);
      
      // Briefly trigger targeted highlight CSS pulse natively
      element.classList.remove("target-highlight-pulse");
      void element.offsetWidth; // trigger reflow
      element.classList.add("target-highlight-pulse");
    }
  };

  const tocLinks = getTocLinks(pathname);

  return (
    <div className="w-full px-6 md:px-12 lg:px-16 flex flex-col md:flex-row gap-12 h-[calc(100vh-5rem)] overflow-hidden select-none">
      
      {/* 1. Locked Left Sidebar Navigation */}
      <aside className="w-full md:w-72 shrink-0 h-full overflow-y-auto pr-6 border-r border-zinc-900 py-10">
        <nav className="space-y-8">
          {menuItems.map((group, idx) => (
            <div key={idx}>
              <h4 className="text-[11px] font-bold font-sans tracking-widest text-zinc-500 uppercase mb-4">
                {group.title}
              </h4>
              <ul className="space-y-2">
                {menuItems[idx].items.map((item, itemIdx) => {
                  const isActive = pathname === item.href;
                  const Icon = item.icon;
                  return (
                    <li key={itemIdx}>
                      <Link
                        href={item.href}
                        className={`group flex items-center gap-3 px-3 py-2 rounded-md text-sm font-semibold transition-all duration-150 ${
                          isActive
                            ? "bg-zinc-900 text-zinc-50 font-bold border-l-2 border-indigo-500 pl-2.5"
                            : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/40"
                        }`}
                      >
                        <Icon size={16} className={isActive ? "text-indigo-400" : "text-zinc-500 group-hover:text-zinc-400"} />
                        {item.label}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>
      </aside>

      {/* 2. Isolated Main Scrollable Content Area & Locked Right Sidebar */}
      <div className="flex-1 flex gap-12 min-w-0 h-full overflow-hidden">
        
        {/* Only the central reading pane has overflow-y-auto scroll! */}
        <div className="flex-1 min-w-0 h-full overflow-y-auto py-10 pr-6 scroll-smooth select-text">
          {children}
        </div>

        {/* Locked Right Sidebar (Table of Contents) */}
        <aside className="hidden xl:block w-56 shrink-0 h-full overflow-y-auto pl-6 border-l border-zinc-900 py-10">
          <h4 className="text-xs font-bold tracking-widest text-zinc-500 uppercase mb-4 font-sans">On this page</h4>
          <ul className="space-y-3 text-sm font-semibold text-zinc-400">
            {tocLinks.map((link, idx) => (
              <li key={idx}>
                <a 
                  href={link.href} 
                  onClick={(e) => handleTocClick(e, link.href)}
                  className="hover:text-zinc-200 transition-colors cursor-pointer"
                >
                  {link.label}
                </a>
              </li>
            ))}
          </ul>
        </aside>
      </div>
    </div>
  );
}
