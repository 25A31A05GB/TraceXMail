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
  Share2
} from 'lucide-react';
import { motion } from 'motion/react';
import { ConnectionStatus } from '../hooks/useWebSocketAlerts';

export type NavTab = 
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
    <aside id="app-sidebar" className="w-64 bg-[#1E293B] border-r border-slate-700 flex flex-col shrink-0 select-none">
      {/* Brand Header */}
      <div className="p-5 flex items-center gap-3 border-b border-slate-800/80">
        <div className="w-9 h-9 bg-blue-600 rounded-lg flex items-center justify-center shadow-md shadow-blue-600/30">
          <ShieldAlert className="w-5 h-5 text-white" />
        </div>
        <div>
          <span className="font-bold text-xl tracking-tight text-white block leading-none">TraceXMail</span>
          <span className="text-[10px] text-slate-400 font-mono tracking-wider uppercase">Email Forensics OS</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 space-y-4 mt-3 overflow-y-auto">
        {/* Core Navigation */}
        <div className="space-y-1">
          <div className="px-3 pb-1 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
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
                className={`relative w-full px-3 py-2 rounded-lg font-medium text-xs flex items-center gap-2.5 cursor-pointer text-left transition-colors duration-200 ${
                  isActive
                    ? 'text-blue-400 font-semibold'
                    : 'text-slate-300 hover:text-slate-100'
                }`}
              >
                {isActive && (
                  <motion.div
                    layoutId="activeNavPill"
                    className="absolute inset-0 bg-blue-600/20 border border-blue-500/30 rounded-lg shadow-sm"
                    transition={{ type: 'spring', stiffness: 450, damping: 35 }}
                  />
                )}
                <Icon className={`relative z-10 w-4 h-4 transition-colors duration-200 ${isActive ? 'text-blue-400' : 'text-slate-400'}`} />
                <span className="relative z-10 flex-1">{item.label}</span>
              </motion.button>
            );
          })}
        </div>

        {/* Forensic Deep Dive Modules */}
        <div className="space-y-1">
          <div className="px-3 pb-1 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
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
                className={`relative w-full px-3 py-2 rounded-lg font-medium text-xs flex items-center gap-2.5 cursor-pointer text-left transition-colors duration-200 ${
                  isActive
                    ? 'text-blue-400 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {isActive && (
                  <motion.div
                    layoutId="activeNavPill"
                    className="absolute inset-0 bg-blue-600/20 border border-blue-500/30 rounded-lg shadow-sm"
                    transition={{ type: 'spring', stiffness: 450, damping: 35 }}
                  />
                )}
                <Icon className={`relative z-10 w-4 h-4 transition-colors duration-200 ${isActive ? 'text-blue-400' : 'text-slate-400'}`} />
                <span className="relative z-10 flex-1">{item.label}</span>
                {item.badge !== undefined && item.badge > 0 && (
                  <span className="relative z-10 bg-rose-600 text-white text-[10px] font-bold px-1.5 py-0.2 rounded-full animate-pulse">
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
          className="w-full bg-blue-600/15 hover:bg-blue-600/25 border border-blue-500/40 text-blue-300 py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 cursor-pointer transition-colors"
        >
          <Upload className="w-3.5 h-3.5" />
          <span>Ingest .EML File</span>
        </motion.button>
      </div>

      {/* Public legal links */}
      <div className="px-3 pb-3 flex items-center justify-center gap-3 text-[10px] font-mono text-slate-500">
        <a
          href="/privacy"
          target="_blank"
          rel="noreferrer"
          className="transition-colors hover:text-slate-300"
        >
          PRIVACY
        </a>
        <span className="text-slate-700">•</span>
        <a
          href="/terms"
          target="_blank"
          rel="noreferrer"
          className="transition-colors hover:text-slate-300"
        >
          TERMS
        </a>
      </div>

      {/* System Status Footer with Dynamic WebSocket indicator */}
      <div className="p-3.5 border-t border-slate-700 bg-slate-900/60">
        <div className="flex items-center justify-between mb-1.5">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                isWsConnected ? 'bg-emerald-400' : isWsReconnecting ? 'bg-amber-400' : 'bg-rose-400'
              }`}></span>
              <span className={`relative inline-flex rounded-full h-2 w-2 ${
                isWsConnected ? 'bg-emerald-500' : isWsReconnecting ? 'bg-amber-500' : 'bg-rose-500'
              }`}></span>
            </span>
            <span className={`text-[11px] font-mono font-semibold flex items-center gap-1 ${
              isWsConnected ? 'text-emerald-400' : isWsReconnecting ? 'text-amber-400' : 'text-rose-400'
            }`}>
              <Radio className="w-3 h-3 inline animate-pulse" /> WS {wsStatus}
            </span>
          </div>
          <span className={`text-[9px] px-1.5 py-0.5 rounded font-mono border ${
            isWsConnected
              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
              : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
          }`}>
            RLS ACTIVE
          </span>
        </div>
        <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono">
          <span>TENANT: org_default_01</span>
          <span>TABLES: 19</span>
        </div>
      </div>
    </aside>
  );
}
