import React, { useEffect, useState, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useAppContext } from '../context/AppContext';
import { Delivery } from '../types';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
}

const CommandPalette: React.FC<CommandPaletteProps> = ({ isOpen, onClose }) => {
  const { sessionToken } = useAppContext();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<Delivery[]>([]);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Focus input when opened and reset state
  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setResults([]);
      setTimeout(() => inputRef.current?.focus(), 10);
    }
  }, [isOpen]);

  // Debounced encrypted search
  useEffect(() => {
    if (!isOpen || !query.trim()) {
      setResults([]);
      return;
    }

    const timer = setTimeout(async () => {
      setLoading(true);
      try {
        const data = await invoke<Delivery[]>('global_search', { sessionToken, query });
        setResults(data || []);
      } catch (err) {
        console.error('Search failed:', err);
        setResults([]);
      } finally {
        setLoading(false);
      }
    }, 300); // 300ms debounce

    return () => clearTimeout(timer);
  }, [query, isOpen, sessionToken]);

  // Handle Escape key
  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [onClose]);

  if (!isOpen) return null;

  return (
    <div 
      className="fixed inset-0 z-[100] bg-black/60 backdrop-blur-sm flex items-start justify-center pt-[15vh] p-4 fade-in"
      onClick={onClose}
    >
      <div 
        className="w-full max-w-2xl bg-[#111b21] rounded-2xl shadow-2xl border border-[#2a3942] overflow-hidden flex flex-col max-h-[60vh]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Input Area */}
        <div className="p-4 border-b border-[#2a3942] flex items-center gap-3">
          <span className="text-xl text-[#8696a0]">🔍</span>
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search deliveries, recipients, files, messages..."
            className="flex-1 bg-transparent text-[#e9edef] text-lg outline-none placeholder-[#8696a0]"
          />
          <kbd className="hidden md:inline-block px-2 py-1 text-xs font-semibold text-[#8696a0] bg-[#202c33] border border-[#2a3942] rounded">ESC</kbd>
        </div>

        {/* Results Area */}
        <div className="overflow-y-auto flex-1">
          {loading && (
            <div className="p-8 text-center text-[#8696a0] animate-pulse">Decrypting and searching vault...</div>
          )}
          
          {!loading && query.trim() && results.length === 0 && (
            <div className="p-8 text-center text-[#8696a0]">No results found.</div>
          )}

          {!loading && results.length > 0 && (
            <ul className="py-2">
              {results.map((d) => (
                <li 
                  key={d.id} 
                  className="px-4 py-3 hover:bg-[#202c33] cursor-pointer transition-colors border-b border-[#202c33] last:border-0"
                  onClick={onClose} // Closes palette on selection
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold text-[#e9edef] truncate">
                      {d.recipient_name || (d.recipient_email as string) || 'Unknown Recipient'}
                    </span>
                    <span className="text-xs text-[#8696a0] shrink-0 ml-2">
                      {new Date(d.scheduled_for).toLocaleDateString()}
                    </span>
                  </div>
                  <div className="text-sm text-[#8696a0] truncate">
                    {d.file_name ? (
                      <span>📎 {d.file_name}</span>
                    ) : (
                      <span>{(d.message_text as string) || 'Empty message'}</span>
                    )}
                  </div>
                  {d.recipient_email && (
                    <div className="text-xs text-[#53bdeb] mt-1 truncate">{d.recipient_email as string}</div>
                  )}
                </li>
              ))}
            </ul>
          )}

          {!loading && !query.trim() && (
            <div className="p-8 text-center text-[#8696a0] text-sm">
              Type to search across your encrypted deliveries, files, and messages.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CommandPalette;