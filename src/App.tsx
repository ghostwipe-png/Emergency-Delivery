import React, { Suspense, lazy, useState, useEffect } from 'react';
import { useAppContext } from './context/AppContext';
import AuthScreen from './components/AuthScreen';
import TosConsent from './components/TosConsent'; // Phase 1 Component
import Dashboard from './components/Dashboard';
import NewDelivery from './components/NewDelivery';
import Settings from './components/Settings';
import CommandPalette from './components/CommandPalette'; // Phase 7 Component
import ChatView from './components/ChatView';
import SocialView from './features/social/SocialView'; // Phase 9: Social Layer
import { useNotifications } from './hooks/useNotifications'; // Phase 5 Hook
import StatusView from './features/social/StatusView';

const Analytics = lazy(() => import('./components/Analytics'));

// Added 'social' and 'status' to the View type
type View = 'dashboard' | 'new' | 'analytics' | 'settings' | 'chat' |  'social' | 'status';

const CURRENT_TOS_VERSION = 1;

const App: React.FC = () => {
  const { user, ready, pending, logout, refreshUser } = useAppContext();
  const [currentView, setCurrentView] = useState<View>('dashboard');
  
  // Phase 7: Command Palette State
  const [isPaletteOpen, setIsPaletteOpen] = useState(false);

  // Phase 5: Initialize background notification polling (Strictly Additive)
  // Placed before early returns to strictly follow the Rules of Hooks.
  useNotifications();

  // Phase 7: Global Command Palette Shortcut (Ctrl+K / Cmd+K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault(); // Prevent browser's default focus search
        setIsPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // 1. Loading State
  if (!ready) {
    return (
      <div className="flex items-center justify-center h-screen bg-[#0b141a] text-[#e9edef]">
        <div className="animate-pulse text-xl font-medium">Loading Emergency Delivery...</div>
      </div>
    );
  }

  // 2. Authentication Gate
  if (!user || pending) {
    return <AuthScreen />;
  }

  // 3. Phase 1: ToS Consent Gate (Blocks Dashboard until accepted)
  const userTosVersion = (user as any)?.tos_version ?? 0;
  if (userTosVersion < CURRENT_TOS_VERSION) {
    return <TosConsent onAccepted={refreshUser} />;
  }

  // 4. View Router
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
    }
  };

  // Safe property access to prevent TS errors if User interface is loosely typed
  const userEmail = user?.email || 'User';
  const userCredits = (user as any)?.credits ?? (user as any)?.delivery_credits ?? 0;
  const userSmsBalance = (user as any)?.sms_balance ?? (user as any)?.smsBalance ?? 0;

  // 5. Authenticated Layout
  return (
    <div className="flex h-screen bg-[#0b141a] text-[#e9edef] overflow-hidden fade-in">
      
      {/* Sidebar (WhatsApp Dark Theme) */}
      <aside className="w-72 bg-[#111b21] flex flex-col p-4 space-y-2">
        
        {/* Brand */}
        <div className="mb-8 px-2 pt-2">
          <h1 className="text-2xl font-bold text-[#00a884] tracking-tight">Emergency Delivery</h1>
          <p className="text-sm text-[#8696a0] mt-1">Secure • Reliable • Timely</p>
        </div>

        {/* Navigation */}
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

          <button
            onClick={() => setCurrentView('chat')}
            className={`nav-item w-full text-left px-4 py-3 rounded-xl flex items-center space-x-3 transition-colors ${
              currentView === 'chat' ? 'nav-item-active bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0] hover:bg-[#202c33]'
            }`}
          >
            <span className="text-xl">💬</span>
            <span className="font-medium">Secure Chat</span>
          </button>

          {/* Phase 9: Standalone Social Layer */}
          <button
            onClick={() => setCurrentView('social')}
            className={`nav-item w-full text-left px-4 py-3 rounded-xl flex items-center space-x-3 transition-colors ${
              currentView === 'social' ? 'nav-item-active bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0] hover:bg-[#202c33]'
            }`}
          >
            <span className="text-xl">🌐</span>
            <span className="font-medium">Social</span>
          </button>
          {/* Phase 11: Status/Stories */}
          <button
            onClick={() => setCurrentView('status')}
            className={`nav-item w-full text-left px-4 py-3 rounded-xl flex items-center space-x-3 transition-colors ${
              currentView === 'status' ? 'nav-item-active bg-[#2a3942] text-[#e9edef]' : 'text-[#8696a0] hover:bg-[#202c33]'
            }`}
          >
            <span className="text-xl">⏱️</span>
            <span className="font-medium">Status</span>
          </button>

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
              <span className="text-[#00a884]">Credits: {userCredits}</span>
              <span className="text-[#53bdeb]">SMS: {userSmsBalance}</span>
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

      {/* Phase 7: Global Command Palette (Strictly Additive) */}
      <CommandPalette isOpen={isPaletteOpen} onClose={() => setIsPaletteOpen(false)} />
    </div>
  );
};

export default App;