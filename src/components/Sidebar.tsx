import { 
  ShieldAlert, 
  Activity, 
  MapPin, 
  Bell, 
  FileText, 
  Network, 
  Terminal, 
  Radio,
  Database,
  Upload,
  Search,
  Layers,
  FolderOpen,
  LayoutDashboard,
  Clock,
  Share2,
  Compass
} from 'lucide-react';
import { motion } from 'motion/react';
import { ConnectionStatus } from '../hooks/useWebSocketAlerts';

export type NavTab = 
  | 'landing'
  | 'dashboard'
  | 'cases'
  | 'campaigns'
  | 'search'
  | 'overview'
  | 'timeline'
  | 'graph'
  | 'hops'
  | 'map'
  | 'logs'
  | 'headers'
  | 'alerts'
  | 'ingest';

interface SidebarProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  alertCount: number;
  wsStatus: ConnectionStatus;
}

export function Sidebar({ activeTab, setActiveTab, alertCount, wsStatus }: SidebarProps) {
  const primaryNavItems = [
    { id: 'landing' as const, label: 'Intel Showcase', icon: Compass },
    { id: 'dashboard' as const, label: 'Dashboard', icon: LayoutDashboard },
    { id: 'cases' as const, label: 'Cases', icon: FolderOpen },
    { id: 'campaigns' as const, label: 'Campaigns', icon: Layers },
    { id: 'search' as const, label: 'Search', icon: Search },
  ];

  const forensicNavItems = [
    { id: 'overview' as const, label: 'Message Overview', icon: Activity },
    { id: 'graph' as const, label: 'Relationship Graph', icon: Share2 },
    { id: 'timeline' as const, label: 'Threat Timeline', icon: Clock },
    { id: 'ingest' as const, label: 'Email Ingestion', icon: Database },
    { id: 'hops' as const, label: 'Hop Traceroute', icon: Network },
    { id: 'map' as const, label: 'Geographic Map', icon: MapPin },
    { id: 'logs' as const, label: 'Analysis Log', icon: Terminal },
    { id: 'headers' as const, label: 'Raw RFC822 / EML', icon: FileText },
    { id: 'alerts' as const, label: 'Live Alerts', icon: Bell, badge: alertCount },
  ];

  const isWsConnected = (wsStatus as string)?.toLowerCase() === 'connected';
  const isWsReconnecting = (wsStatus as string)?.toLowerCase() === 'reconnecting' || (wsStatus as string)?.toLowerCase() === 'connecting';

  return (
    <aside id="app-sidebar" className="w-64 bg-[#1a1712] border-r border-[#3a352c] flex flex-col shrink-0 select-none">
      {/* Brand Header with Exact Forensic Identity */}
      <button
        onClick={() => setActiveTab('landing')}
        className="p-5 flex items-center gap-3 border-b border-[#3a352c] text-left hover:bg-[#221e17] transition-colors cursor-pointer"
      >
        <div className="w-[24px] h-[24px] border-[1.5px] border-[var(--thread)] rounded-full relative shrink-0">
          <div className="absolute inset-[5px] rounded-full bg-[var(--thread)]" />
        </div>
        <div>
          <span className="font-display font-bold text-xl tracking-tight text-[#ede6d8] block leading-none">
            TraceXMail
          </span>
          <span className="text-[10.5px] text-[#b9af9c] font-mono tracking-wider">
            CASE-XM-01
          </span>
        </div>
      </button>

      {/* Navigation */}
      <nav className="flex-1 px-3 space-y-4 mt-3 overflow-y-auto">
        {/* Core Navigation */}
        <div className="space-y-1">
          <div className="px-3 pb-1 text-[10px] font-mono font-medium text-[#b9af9c] uppercase tracking-wider">
            Workspace
          </div>
          {primaryNavItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <motion.button
                key={item.id}
                id={`nav-btn-${item.id}`}
                onClick={() => setActiveTab(item.id)}
                whileHover={{ x: 3 }}
                whileTap={{ scale: 0.98 }}
                transition={{ type: 'spring', stiffness: 400, damping: 25 }}
                className={`relative w-full px-3 py-2 rounded-md font-sans text-xs flex items-center gap-2.5 cursor-pointer text-left transition-colors duration-200 ${
                  isActive
                    ? 'text-[#ede6d8] font-semibold'
                    : 'text-[#b9af9c] hover:text-[#ede6d8]'
                }`}
              >
                {isActive && (
                  <motion.div
                    layoutId="activeNavPill"
                    className="absolute inset-0 bg-[#b23a2e]/20 border border-[#b23a2e]/40 rounded-md shadow-xs"
                    transition={{ type: 'spring', stiffness: 450, damping: 35 }}
                  />
                )}
                <Icon className={`relative z-10 w-4 h-4 transition-colors duration-200 ${isActive ? 'text-[#e8836f]' : 'text-[#8a8070]'}`} />
                <span className="relative z-10 flex-1">{item.label}</span>
              </motion.button>
            );
          })}
        </div>

        {/* Forensic Deep Dive Modules */}
        <div className="space-y-1">
          <div className="px-3 pb-1 text-[10px] font-mono font-medium text-[#b9af9c] uppercase tracking-wider">
            Forensic Inspection
          </div>
          {forensicNavItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <motion.button
                key={item.id}
                id={`nav-btn-${item.id}`}
                onClick={() => setActiveTab(item.id)}
                whileHover={{ x: 3 }}
                whileTap={{ scale: 0.98 }}
                transition={{ type: 'spring', stiffness: 400, damping: 25 }}
                className={`relative w-full px-3 py-2 rounded-md font-sans text-xs flex items-center gap-2.5 cursor-pointer text-left transition-colors duration-200 ${
                  isActive
                    ? 'text-[#ede6d8] font-semibold'
                    : 'text-[#8a8070] hover:text-[#ede6d8]'
                }`}
              >
                {isActive && (
                  <motion.div
                    layoutId="activeNavPill"
                    className="absolute inset-0 bg-[#7fa3ba]/15 border border-[#7fa3ba]/30 rounded-md shadow-xs"
                    transition={{ type: 'spring', stiffness: 450, damping: 35 }}
                  />
                )}
                <Icon className={`relative z-10 w-4 h-4 transition-colors duration-200 ${isActive ? 'text-[#7fa3ba]' : 'text-[#6b6255]'}`} />
                <span className="relative z-10 flex-1">{item.label}</span>
                {item.badge !== undefined && item.badge > 0 && (
                  <span className="relative z-10 bg-[#b23a2e] text-[#ede6d8] text-[10px] font-mono font-bold px-1.5 py-0.2 rounded-full animate-pulse">
                    {item.badge}
                  </span>
                )}
              </motion.button>
            );
          })}
        </div>
      </nav>

      {/* Quick Ingest Button in Sidebar */}
      <div className="p-3">
        <motion.button
          onClick={() => setActiveTab('ingest')}
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.97 }}
          transition={{ type: 'spring', stiffness: 400, damping: 25 }}
          className="w-full bg-[#26221b] hover:bg-[#322c23] border border-[#3a352c] text-[#ede6d8] py-2 px-3 rounded-md text-xs font-semibold flex items-center justify-center gap-2 cursor-pointer transition-colors"
        >
          <Upload className="w-3.5 h-3.5 text-[var(--thread)]" />
          <span>Ingest .EML File</span>
        </motion.button>
      </div>

      {/* Public legal links */}
      <div className="px-3 pb-3 flex items-center justify-center gap-3 text-[10px] font-mono text-[#8a8070]">
        <a
          href="/privacy"
          target="_blank"
          rel="noreferrer"
          className="transition-colors hover:text-[#ede6d8]"
        >
          PRIVACY
        </a>
        <span className="text-[#3a352c]">•</span>
        <a
          href="/terms"
          target="_blank"
          rel="noreferrer"
          className="transition-colors hover:text-[#ede6d8]"
        >
          TERMS
        </a>
      </div>
    </aside>
  );
}
