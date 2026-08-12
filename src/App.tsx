import React, { Suspense, lazy, useState, useEffect } from 'react';
import { useAppContext } from './context/AppContext';
import AuthScreen from './components/AuthScreen';
import TosConsent from './components/TosConsent';
import Dashboard from './components/Dashboard';
import NewDelivery from './components/NewDelivery';
import Settings from './components/Settings';
import CommandPalette from './components/CommandPalette';
import ChatView from './components/ChatView';
import SocialView from './features/social/SocialView';
import { useNotifications } from './hooks/useNotifications';
import StatusView from './features/social/StatusView';
import { useUpdater } from './hooks/useUpdater';
import GuardianView from './components/GuardianView';
import InheritanceView from './components/InheritanceView';

const Analytics = lazy(() => import('./components/Analytics'));

// View type keeps all routes available for future re-enablement
type View = 'dashboard' | 'new' | 'analytics' | 'settings' |  'chat' | 'social' | 'status' |  'guardian' | 'inheritance';

const CURRENT_TOS_VERSION = 1;

const App: React.FC = () => {
  const { user, ready, pending, logout, refreshUser } = useAppContext();
  const [currentView, setCurrentView] = useState<View>('dashboard');
  
  const [isPaletteOpen, setIsPaletteOpen] = useState(false);

  useNotifications();
  useUpdater();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  if (!ready) {
    return (
      <div className="flex items-center justify-center h-screen bg-[#0b141a] text-[#e9edef]">
        <div className="animate-pulse text-xl font-medium">Loading Emergency Delivery...</div>
      </div>
    );
  }

  if (!user || pending) {
    return <AuthScreen />;
  }

  const userTosVersion = (user as any)?.tos_version ?? 0;
  if (userTosVersion < CURRENT_TOS_VERSION) {
    return <TosConsent onAccepted={refreshUser} />;
  }

  const renderView = () => {
    switch (currentView) {
      case 'dashboard':
        return <Dashboard onNavigate={setCurrentView} />;
      case 'new':
        return <NewDelivery />;
      case 'analytics':
        return (
          <Suspense fallback={<div className="p-6 text-center text-[#8696a0] animate-pulse">Loading charts...</div>}>
            <Analytics />
          </Suspense>
        );
      case 'settings':
        return <Settings />;
      case 'chat':
        return <ChatView />;
      case 'social':
        return <SocialView />;
      case 'status':
        return <StatusView />;
      case 'guardian':
        return <GuardianView />;
      case 'inheritance':
        return <InheritanceView />;
    }
  };

  const userEmail = user?.email || 'User';
  const userCredits = (user as any)?.credits ?? (user as any)?.delivery_credits ?? 0;
  const userSmsBalance = (user as any)?.sms_balance ?? (user as any)?.smsBalance ?? 0;

  return (
    <div className="flex h-screen bg-[#0b141a] text-[#e9edef] overflow-hidden fade-in">
      
      {/* Sidebar (WhatsApp Dark Theme) */}
      <aside className="w-72 bg-[#111b21] flex flex-col p-4 space-y-2">
        
        {/* Brand */}
        <div className="mb-8 px-2 pt-2">
          <h1 className="text-2xl font-bold text-[#00a884] tracking-tight">Emergency Delivery</h1>
          <p className="text-sm text-[#8696a0] mt-1">Secure • Reliable • Timely</p>
        </div>

        {/* Navigation — Core Delivery Operations Only */}
        <nav className="flex-1 space-y-1">
          <button
            onClick={() => setCurrentView('dashboard')}
            className={`nav-item w-full text-left px-4 py-3 rounded-xl flex items-center space-x-3 transition-colors ${
              currentView === 'dashboard' ? 'nav-item-active bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0] hover:bg-[#202c33]'
            }`}
          >
            <span className="text-xl">🏠</span>
            <span className="font-medium">Dashboard</span>
          </button>
          
          <button
            onClick={() => setCurrentView('new')}
            className={`nav-item w-full text-left px-4 py-3 rounded-xl flex items-center space-x-3 transition-colors ${
              currentView === 'new' ? 'nav-item-active bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0] hover:bg-[#202c33]'
            }`}
          >
            <span className="text-xl">✏️</span>
            <span className="font-medium">New Delivery</span>
          </button>

          <button
            onClick={() => setCurrentView('analytics')}
            className={`nav-item w-full text-left px-4 py-3 rounded-xl flex items-center space-x-3 transition-colors ${
              currentView === 'analytics' ? 'nav-item-active bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0] hover:bg-[#202c33]'
            }`}
          >
            <span className="text-xl">📊</span>
            <span className="font-medium">Analytics</span>
          </button>

          <button onClick={() => setCurrentView('guardian')}
            className={`nav-item w-full text-left px-4 py-3 rounded-xl flex items-center space-x-3 transition-colors ${
             currentView === 'guardian' ? 'nav-item-active bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0] hover:bg-[#202c33]'}`}>
             <span className="text-xl">🛡️</span><span className="font-medium">Guardian</span>
              </button>

          <button
            onClick={() => setCurrentView('inheritance')}
            className={`nav-item w-full text-left px-4 py-3 rounded-xl flex items-center space-x-3 transition-colors ${
              currentView === 'inheritance' ? 'nav-item-active bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0] hover:bg-[#202c33]'}`}>
            <span className="text-xl">🧬</span><span className="font-medium">Inheritance</span>
          </button>

          {/* ============================================================
             FUTURE FEATURES — Commented out for focused MVP launch.
             These features are fully built and ready to re-enable
             whenever users request them. Simply uncomment the blocks below.
             ============================================================ */}

          {/* [SECURE CHAT — FUTURE]
          <button
            onClick={() => setCurrentView('chat')}
            className={`nav-item w-full text-left px-4 py-3 rounded-xl flex items-center space-x-3 transition-colors ${
              currentView === 'chat' ? 'nav-item-active bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0] hover:bg-[#202c33]'
            }`}
          >
            <span className="text-xl">💬</span>
            <span className="font-medium">Secure Chat</span>
          </button>
          */}

          {/* [SOCIAL LAYER — FUTURE]
          <button
            onClick={() => setCurrentView('social')}
            className={`nav-item w-full text-left px-4 py-3 rounded-xl flex items-center space-x-3 transition-colors ${
              currentView === 'social' ? 'nav-item-active bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0] hover:bg-[#202c33]'
            }`}
          >
            <span className="text-xl">🌐</span>
            <span className="font-medium">Social</span>
          </button>
          */}

          {/* [STATUS / STORIES — FUTURE]
          <button
            onClick={() => setCurrentView('status')}
            className={`nav-item w-full text-left px-4 py-3 rounded-xl flex items-center space-x-3 transition-colors ${
              currentView === 'status' ? 'nav-item-active bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0] hover:bg-[#202c33]'
            }`}
          >
            <span className="text-xl">⏱️</span>
            <span className="font-medium">Status</span>
          </button>
          */}

          {/* ============================================================
             END OF FUTURE FEATURES
             ============================================================ */}

          <button
            onClick={() => setCurrentView('settings')}
            className={`nav-item w-full text-left px-4 py-3 rounded-xl flex items-center space-x-3 transition-colors ${
              currentView === 'settings' ? 'nav-item-active bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0] hover:bg-[#202c33]'
            }`}
          >
            <span className="text-xl">⚙️</span>
            <span className="font-medium">Settings</span>
          </button>
        </nav>

        {/* User Info & Actions */}
        <div className="mt-auto pt-4">
          <div className="px-2 mb-4">
            <p className="text-xs uppercase tracking-wider text-[#8696a0] mb-1">Logged in as</p>
            <p className="font-medium text-[#e9edef] truncate" title={userEmail}>{userEmail}</p>
            <div className="flex gap-3 mt-2 text-xs font-semibold">
              <span className="text-[#00a884] flex items-center gap-1" title="Email Credits">
                ✉️ <span>{userCredits}</span>
              </span>
              <span className="text-[#53bdeb] flex items-center gap-1" title="SMS Credits">
                📱 <span>{userSmsBalance}</span>
              </span>
            </div>
          </div>
          <button
            onClick={() => { void logout(); }}
            className="btn-ghost w-full px-4 py-2.5 rounded-xl bg-[#202c33] hover:bg-[#2a3942] text-[#e9edef] transition-colors text-sm font-medium"
          >
            Sign Out
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 overflow-y-auto bg-[#0b141a]">
        <div className="max-w-6xl mx-auto p-8">
          {renderView()}
        </div>
      </main>

      <CommandPalette isOpen={isPaletteOpen} onClose={() => setIsPaletteOpen(false)} />
    </div>
  );
};

export default App;