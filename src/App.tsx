import { useState, useEffect } from 'react';
import { LegalPage } from './components/LegalPage';
import { Sidebar, NavTab } from './components/Sidebar';
import { Header } from './components/Header';
import { DashboardView } from './components/DashboardView';
import { CasesView } from './components/CasesView';
import { CampaignsView } from './components/CampaignsView';
import { SearchView } from './components/SearchView';
import { OverviewView } from './components/OverviewView';
import { ThreatTimelineView } from './components/ThreatTimelineView';
import { RelationshipGraphView } from './components/RelationshipGraphView';
import { HopTracerouteView } from './components/HopTracerouteView';
import { MapView } from './components/MapView';
import { ThreatLogView } from './components/ThreatLogView';
import { RawHeaderView } from './components/RawHeaderView';
import { AlertsView } from './components/AlertsView';
import { IngestionPipelineView } from './components/IngestionPipelineView';
import { NewAnalysisModal } from './components/NewAnalysisModal';
import { ReportModal } from './components/ReportModal';
import { PrivacyComplianceModal } from './components/PrivacyComplianceModal';
import { AlertToast } from './components/AlertToast';
import { LandingView } from './components/LandingView';
import { AuthModal } from './components/AuthModal';
import { SAMPLE_ANALYSES } from './data/samples';
import { EmailAnalysis } from './types';
import { useWebSocketAlerts, WebSocketAlert } from './hooks/useWebSocketAlerts';
import { PrivacyConfig, loadPrivacyConfig, savePrivacyConfig } from './utils/privacyCompliance';
import { subscribeSession, SessionUser } from './lib/api';

export default function App() {
  const publicPath = window.location.pathname;

  if (publicPath === '/privacy') {
    return <LegalPage type="privacy" />;
  }

  if (publicPath === '/terms') {
    return <LegalPage type="terms" />;
  }


  const [currentAnalysis, setCurrentAnalysis] = useState<EmailAnalysis>(SAMPLE_ANALYSES[0]);
  const [activeTab, setActiveTab] = useState<NavTab>('landing');
  const [isNewModalOpen, setIsNewModalOpen] = useState<boolean>(false);
  const [isReportModalOpen, setIsReportModalOpen] = useState<boolean>(false);
  const [isPrivacyModalOpen, setIsPrivacyModalOpen] = useState<boolean>(false);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);
  const [sessionUser, setSessionUser] = useState<SessionUser | null>(null);
  const [privacyConfig, setPrivacyConfig] = useState<PrivacyConfig>(() => loadPrivacyConfig());
  const [casesRefreshSignal, setCasesRefreshSignal] = useState<number>(0);
  const [showDemoCases, setShowDemoCases] = useState<boolean>(() => {
    try {
      return localStorage.getItem('tracexmail_show_demo_cases') === 'true';
    } catch {
      return false;
    }
  });

  useEffect(() => {
    return subscribeSession((sess) => {
      setSessionUser(sess.user);
    });
  }, []);

  const handleToggleDemoCases = () => {
    setShowDemoCases(prev => {
      const next = !prev;
      try {
        localStorage.setItem('tracexmail_show_demo_cases', String(next));
      } catch {}
      return next;
    });
  };

  const handleUpdatePrivacyConfig = (newCfg: PrivacyConfig) => {
    setPrivacyConfig(newCfg);
    savePrivacyConfig(newCfg);
  };

  // Real-Time WebSockets Alerting Hook
  const {
    alerts: liveAlerts,
    activeToast,
    status: wsStatus,
    unreadCount,
    soundEnabled,
    setSoundEnabled,
    dismissToast,
    broadcastTestAlert,
    reconnect: reconnectWs
  } = useWebSocketAlerts();

  const handleAnalysisCreated = (newAnalysis: EmailAnalysis) => {
    setCurrentAnalysis(newAnalysis);
    setActiveTab('overview');
    setCasesRefreshSignal(prev => prev + 1);
  };

  const handleToastInspect = (alert: WebSocketAlert) => {
    const matchingSample = SAMPLE_ANALYSES.find(s => s.id === alert.case_id) || SAMPLE_ANALYSES[0];
    setCurrentAnalysis(matchingSample);
    setActiveTab('overview');
  };

  if (activeTab === 'landing') {
    return (
      <div className="relative min-h-screen w-screen bg-[#14120f] text-[#ede6d8] overflow-y-auto">
        <LandingView
          onOpenConsole={() => setActiveTab('overview')}
          onOpenTrace={() => setActiveTab('ingest')}
          onRequestAccess={() => setIsAuthModalOpen(true)}
          onSelectCase={(analysis) => {
            setCurrentAnalysis(analysis);
            setActiveTab('overview');
          }}
        />
        {isAuthModalOpen && (
          <AuthModal isOpen={isAuthModalOpen} onClose={() => setIsAuthModalOpen(false)} currentUser={sessionUser} />
        )}
      </div>
    );
  }

  return (
    <div className="flex h-screen w-screen bg-[#14120f] text-[#ede6d8] overflow-hidden font-sans select-text">
      {/* Sidebar with dynamic WebSocket connection status and real-time badge count */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        alertCount={unreadCount}
        wsStatus={wsStatus}
      />

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col h-full bg-[#14120f] min-w-0 overflow-hidden">
        {/* Top Header */}
        <Header
          currentAnalysis={currentAnalysis}
          onSelectAnalysis={setCurrentAnalysis}
          onOpenNewModal={() => setIsNewModalOpen(true)}
          onOpenReportModal={() => setIsReportModalOpen(true)}
          onOpenPrivacyModal={() => setIsPrivacyModalOpen(true)}
          privacyConfig={privacyConfig}
          showDemoCases={showDemoCases}
          onToggleDemoCases={handleToggleDemoCases}
        />

        {/* View Switcher Container */}
        <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
          {activeTab === 'dashboard' && (
            <DashboardView
              onSelectAnalysis={setCurrentAnalysis}
              onNavigateToTab={setActiveTab}
            />
          )}

          {activeTab === 'cases' && (
            <CasesView
              onSelectAnalysis={setCurrentAnalysis}
              onNavigateToOverview={() => setActiveTab('overview')}
              onOpenNewModal={() => setIsNewModalOpen(true)}
              refreshSignal={casesRefreshSignal}
              showDemoCases={showDemoCases}
              onToggleDemoCases={handleToggleDemoCases}
            />
          )}

          {activeTab === 'campaigns' && (
            <CampaignsView />
          )}

          {activeTab === 'search' && (
            <SearchView
              onSelectAnalysis={setCurrentAnalysis}
              onNavigateToOverview={() => setActiveTab('overview')}
              showDemoCases={showDemoCases}
              currentAnalysis={currentAnalysis}
              onToggleDemoCases={handleToggleDemoCases}
            />
          )}

          {activeTab === 'overview' && (
            <OverviewView
              analysis={currentAnalysis}
              onNavigateToMap={() => setActiveTab('map')}
              onNavigateToLogs={() => setActiveTab('logs')}
              onNavigateToHeaders={() => setActiveTab('headers')}
              onNavigateToTimeline={() => setActiveTab('timeline')}
              onNavigateToGraph={() => setActiveTab('graph')}
              onOpenNewModal={() => setIsNewModalOpen(true)}
              onOpenReportModal={() => setIsReportModalOpen(true)}
            />
          )}

          {activeTab === 'graph' && (
            <div className="flex-1 p-6 overflow-hidden flex flex-col h-full bg-[#0F172A]">
              <RelationshipGraphView
                analysis={currentAnalysis}
                caseId={currentAnalysis?.id}
              />
            </div>
          )}

          {activeTab === 'timeline' && (
            <ThreatTimelineView
              analysis={currentAnalysis}
              onSelectAnalysis={setCurrentAnalysis}
              onNavigateToOverview={() => setActiveTab('overview')}
              showDemoCases={showDemoCases}
            />
          )}

          {activeTab === 'ingest' && (
            <IngestionPipelineView
              onSelectAnalysis={handleAnalysisCreated}
              onNavigateToOverview={() => setActiveTab('overview')}
            />
          )}

          {activeTab === 'hops' && (
            <HopTracerouteView analysis={currentAnalysis} />
          )}

          {activeTab === 'map' && (
            <MapView analysis={currentAnalysis} />
          )}

          {activeTab === 'logs' && (
            <ThreatLogView analysis={currentAnalysis} />
          )}

          {activeTab === 'headers' && (
            <RawHeaderView analysis={currentAnalysis} />
          )}

          {activeTab === 'alerts' && (
            <AlertsView
              currentAnalysis={currentAnalysis}
              onSelectAnalysis={setCurrentAnalysis}
              onNavigateToOverview={() => setActiveTab('overview')}
              liveAlerts={liveAlerts}
              wsStatus={wsStatus}
              soundEnabled={soundEnabled}
              onToggleSound={() => setSoundEnabled(!soundEnabled)}
              onBroadcastTestAlert={broadcastTestAlert}
              onReconnectWs={reconnectWs}
            />
          )}
        </div>
      </main>

      {/* Real-time WebSocket Alert Toast */}
      <AlertToast
        alert={activeToast}
        onDismiss={dismissToast}
        onInspect={handleToastInspect}
      />

      {/* Modal for Raw Email Analysis & Ingestion */}
      {isNewModalOpen && (
        <NewAnalysisModal
          isOpen={isNewModalOpen}
          onClose={() => setIsNewModalOpen(false)}
          onAnalysisCreated={handleAnalysisCreated}
        />
      )}

      {/* Forensic Report Modal */}
      {isReportModalOpen && (
        <ReportModal
          isOpen={isReportModalOpen}
          onClose={() => setIsReportModalOpen(false)}
          analysis={currentAnalysis}
          privacyConfig={privacyConfig}
        />
      )}

      {/* Privacy, Legal & Compliance Safeguards Modal */}
      {isPrivacyModalOpen && (
        <PrivacyComplianceModal
          isOpen={isPrivacyModalOpen}
          onClose={() => setIsPrivacyModalOpen(false)}
          config={privacyConfig}
          onChangeConfig={handleUpdatePrivacyConfig}
          currentDate={currentAnalysis?.date}
        />
      )}
    </div>
  );
}
