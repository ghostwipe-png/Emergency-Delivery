import { useEffect, useState, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen, UnlistenFn } from '@tauri-apps/api/event';
import { useAppContext } from '../context/AppContext';
import { useWebRTC, CallSignal } from '../features/calls/useWebRTC';
import CallOverlay from '../features/calls/CallOverlay';

interface Channel { id: string; name: string; channel_dek: string; }
interface Message {
  id: string; sender_id: string; ciphertext: string; plaintext?: string; created_at: string;
  type?: 'text' | 'file'; file_key?: string; file_name?: string; file_type?: string;
  status?: 'sending' | 'sent' | 'failed'; blob_url?: string;
  action?: 'send' | 'edit' | 'delete' | 'signal'; target_id?: string;
  reply_to_id?: string; reply_preview?: string; edited?: boolean;
}

const EMOJIS = ['😀', '😂', '😍', '🥳', '🤔', '👍', '👎', '🔥', '🎉', '❤️', '🚀', '🛡️'];

function uint8ToBase64(u8: Uint8Array): string {
  let binary = ''; const len = u8.byteLength;
  for (let i = 0; i < len; i++) binary += String.fromCharCode(u8[i]);
  return btoa(binary);
}
function base64ToUint8(b64: string): Uint8Array {
  const binary = atob(b64); const len = binary.length; const buffer = new ArrayBuffer(len);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function generateDek(): Promise<string> {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const raw = await crypto.subtle.exportKey("raw", key);
  return Array.from(new Uint8Array(raw)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function encryptMessage(dekHex: string, plaintext: string): Promise<string> {
  const dekBytes = base64ToUint8(btoa(dekHex.match(/.{1,2}/g)!.map(b => String.fromCharCode(parseInt(b, 16))).join('')));
  const key = await crypto.subtle.importKey("raw", dekBytes.buffer as ArrayBuffer, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  const combined = new Uint8Array(iv.length + ct.byteLength);
  combined.set(iv, 0); combined.set(new Uint8Array(ct), iv.length);
  return uint8ToBase64(combined);
}

async function decryptMessage(dekHex: string, ciphertextB64: string): Promise<string> {
  const dekBytes = base64ToUint8(btoa(dekHex.match(/.{1,2}/g)!.map(b => String.fromCharCode(parseInt(b, 16))).join('')));
  const key = await crypto.subtle.importKey("raw", dekBytes.buffer as ArrayBuffer, "AES-GCM", false, ["decrypt"]);
  const combined = base64ToUint8(ciphertextB64);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: combined.slice(0, 12) }, key, combined.slice(12));
  return new TextDecoder().decode(pt);
}

async function encryptFile(dekHex: string, file: File): Promise<string> {
  const dekBytes = base64ToUint8(btoa(dekHex.match(/.{1,2}/g)!.map(b => String.fromCharCode(parseInt(b, 16))).join('')));
  const key = await crypto.subtle.importKey("raw", dekBytes.buffer as ArrayBuffer, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, await file.arrayBuffer());
  const combined = new Uint8Array(iv.length + ct.byteLength);
  combined.set(iv, 0); combined.set(new Uint8Array(ct), iv.length);
  return uint8ToBase64(combined);
}

async function decryptFileToUrl(dekHex: string, ciphertextB64: string, mimeType: string): Promise<string> {
  const dekBytes = base64ToUint8(btoa(dekHex.match(/.{1,2}/g)!.map(b => String.fromCharCode(parseInt(b, 16))).join('')));
  const key = await crypto.subtle.importKey("raw", dekBytes.buffer as ArrayBuffer, "AES-GCM", false, ["decrypt"]);
  const combined = base64ToUint8(ciphertextB64);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: combined.slice(0, 12) }, key, combined.slice(12));
  const blob = new Blob([pt], { type: mimeType });
  return URL.createObjectURL(blob);
}

export default function ChatView() {
  const { sessionToken, user } = useAppContext();
  const [channels, setChannels] = useState<Channel[]>([]);
  const [activeChannel, setActiveChannel] = useState<Channel | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [showEmojis, setShowEmojis] = useState(false);
  const [newChannelName, setNewChannelName] = useState('');
  const [wsStatus, setWsStatus] = useState<'disconnected' | 'connecting' | 'connected'>('disconnected');
  
  const [replyingTo, setReplyingTo] = useState<Message | null>(null);
  const [editingMessage, setEditingMessage] = useState<Message | null>(null);
  
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const unlistenRef = useRef<UnlistenFn | null>(null);

  // Phase 11: WebRTC Hook
  const sendSignal = (signal: CallSignal) => {
    if (activeChannel && sessionToken) {
      const payloadStr = JSON.stringify({ ...signal, action: 'signal' });
      invoke('send_chat_message', { sessionToken, channelId: activeChannel.id, ciphertext: payloadStr }).catch(console.error);
    }
  };
  const { localStream, remoteStream, callState, pendingOffer, startCall, acceptCall, handleSignal, hangUp } = useWebRTC(sendSignal);

  useEffect(() => {
    if (!sessionToken) return;
    invoke<Channel[]>('get_chat_channels', { sessionToken }).then(setChannels);
  }, [sessionToken]);

  useEffect(() => {
    const setupListener = async () => {
      if (unlistenRef.current) unlistenRef.current();
      unlistenRef.current = await listen<any>('chat-message-received', async (event) => {
        const { channel_id, payload } = event.payload;
        const parsed = JSON.parse(payload);
        
        if (activeChannel && activeChannel.id === channel_id) {
          // Phase 11: Handle Call Signaling
          if (parsed.action === 'signal') {
            handleSignal(parsed);
            return;
          }

          if (parsed.action === 'delete') {
            setMessages(prev => prev.filter(m => m.id !== parsed.target_id));
            return;
          }
          if (parsed.action === 'edit') {
            setMessages(prev => prev.map(m => m.id === parsed.target_id ? { ...m, ...parsed, edited: true } : m));
            return;
          }

          let msg: Message = { ...parsed, created_at: new Date(parsed.ts || Date.now()).toISOString(), status: 'sent' };
          if (msg.type === 'file') {
             msg.plaintext = `[File: ${msg.file_name}]`;
             if (msg.file_type?.startsWith('image/') && msg.file_key) {
               try {
                 const b64 = await invoke<string>('download_chat_blob', { sessionToken, fileKey: msg.file_key });
                 msg.blob_url = await decryptFileToUrl(activeChannel.channel_dek, b64, msg.file_type!);
               } catch { msg.plaintext = '[Failed to load image]'; }
             }
          } else {
             try { msg.plaintext = await decryptMessage(activeChannel.channel_dek, parsed.ciphertext); } 
             catch { msg.plaintext = '[Decryption failed]'; }
          }
          setMessages(prev => [...prev, msg]);
        }
      });
    };
    setupListener();
    return () => { if (unlistenRef.current) unlistenRef.current(); };
  }, [activeChannel, sessionToken, handleSignal]);

  useEffect(() => { messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

  const loadMessages = async (channel: Channel) => {
    setActiveChannel(channel);
    setWsStatus('connecting');
    setMessages([]);
    setReplyingTo(null);
    setEditingMessage(null);
    setInput('');
    
    invoke('join_chat_channel', { channelId: channel.id })
      .then(() => setWsStatus('connected'))
      .catch(() => setWsStatus('disconnected'));

    const raw = await invoke<any[]>('get_chat_messages', { channelId: channel.id });
    const decrypted: Message[] = [];
    for (const m of raw) {
      try {
         const payload = JSON.parse(m.ciphertext);
         let msg: Message = { ...m, ...payload, status: 'sent' };
         if (payload.type === 'file') {
             msg.plaintext = `[File: ${payload.file_name}]`;
             if (payload.file_type?.startsWith('image/') && payload.file_key) {
                try {
                  const b64 = await invoke<string>('download_chat_blob', { sessionToken, fileKey: payload.file_key });
                  msg.blob_url = await decryptFileToUrl(channel.channel_dek, b64, payload.file_type);
                } catch {}
             }
         } else {
             msg.plaintext = await decryptMessage(channel.channel_dek, payload.ciphertext);
         }
         decrypted.push(msg);
      } catch { decrypted.push({ ...m, plaintext: '[Error]' }); }
    }
    setMessages(decrypted);
  };

  const handleCreateChannel = async () => {
    if (!newChannelName.trim() || !sessionToken) return;
    const dekHex = await generateDek();
    const id = await invoke<string>('create_chat_channel', { sessionToken, name: newChannelName.trim(), channelDekHex: dekHex });
    const newCh = { id, name: newChannelName.trim(), channel_dek: dekHex };
    setChannels(prev => [newCh, ...prev]);
    setNewChannelName('');
    loadMessages(newCh);
  };

  const handleSend = async () => {
    if (!input.trim() || !activeChannel || !sessionToken) return;
    
    let payload: any;
    const msgId = crypto.randomUUID();

    if (editingMessage) {
      payload = { 
        id: msgId, action: 'edit', target_id: editingMessage.id, 
        type: 'text', ciphertext: await encryptMessage(activeChannel.channel_dek, input.trim()) 
      };
    } else {
      payload = { 
        id: msgId, action: 'send', type: 'text', 
        ciphertext: await encryptMessage(activeChannel.channel_dek, input.trim()),
        reply_to_id: replyingTo?.id,
        reply_preview: replyingTo?.plaintext?.slice(0, 50)
      };
    }

    const payloadStr = JSON.stringify(payload);
    const tempMsg: Message = { 
      id: editingMessage ? editingMessage.id : msgId, 
      sender_id: (user as any)?.id || 'me', 
      ciphertext: payloadStr, 
      plaintext: input.trim(), 
      created_at: new Date().toISOString(), 
      type: 'text', 
      status: 'sending',
      edited: !!editingMessage
    };
    
    if (editingMessage) {
      setMessages(prev => prev.map(m => m.id === editingMessage.id ? tempMsg : m));
    } else {
      setMessages(prev => [...prev, tempMsg]);
    }
    
    setInput('');
    setReplyingTo(null);
    setEditingMessage(null);

    try {
      await invoke('send_chat_message', { sessionToken, channelId: activeChannel.id, ciphertext: payloadStr });
      setMessages(prev => prev.map(m => m.id === tempMsg.id ? { ...m, status: 'sent' } : m));
    } catch {
      setMessages(prev => prev.map(m => m.id === tempMsg.id ? { ...m, status: 'failed' } : m));
    }
  };

  const handleDelete = async (targetId: string) => {
    if (!activeChannel || !sessionToken) return;
    const payload = { id: crypto.randomUUID(), action: 'delete', target_id: targetId };
    const payloadStr = JSON.stringify(payload);
    
    setMessages(prev => prev.filter(m => m.id !== targetId));
    await invoke('send_chat_message', { sessionToken, channelId: activeChannel.id, ciphertext: payloadStr });
  };

  const startEdit = (msg: Message) => {
    setEditingMessage(msg);
    setInput(msg.plaintext || '');
  };

  const cancelEdit = () => {
    setEditingMessage(null);
    setInput('');
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !activeChannel || !sessionToken) return;
    if (file.size > 20 * 1024 * 1024) { alert("Max file size is 20MB for chat."); return; }

    const tempId = crypto.randomUUID();
    const tempMsg: Message = { id: tempId, sender_id: (user as any)?.id || 'me', ciphertext: '', plaintext: `Encrypting ${file.name}...`, created_at: new Date().toISOString(), type: 'file', status: 'sending' };
    setMessages(prev => [...prev, tempMsg]);

    try {
      const encryptedB64 = await encryptFile(activeChannel.channel_dek, file);
      const fileKey = await invoke<string>('upload_chat_blob', {
        sessionToken, fileName: file.name, fileType: file.type, fileDataB64: encryptedB64
      });
      const payload = { id: tempId, action: 'send' as const, type: 'file' as const, file_key: fileKey, file_name: file.name, file_type: file.type, file_size: file.size };
      const payloadStr = JSON.stringify(payload);
      
      await invoke('send_chat_message', { sessionToken, channelId: activeChannel.id, ciphertext: payloadStr });
      
      let blobUrl = undefined;
      if (file.type.startsWith('image/')) {
         blobUrl = await decryptFileToUrl(activeChannel.channel_dek, encryptedB64, file.type);
      }

      setMessages(prev => prev.map(m => m.id === tempId ? { 
        ...m, ...payload, ciphertext: payloadStr, plaintext: `[File: ${file.name}]`, status: 'sent', blob_url: blobUrl 
      } : m));
      
    } catch (err) {
      console.error(err);
      setMessages(prev => prev.map(m => m.id === tempId ? { ...m, plaintext: 'Failed to send file', status: 'failed' } : m));
    }
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="flex h-[calc(100vh-4rem)] bg-[#0b141a] rounded-2xl overflow-hidden border border-[#202c33] shadow-2xl">
      <div className="w-80 bg-[#111b21] border-r border-[#202c33] flex flex-col">
        <div className="p-4 border-b border-[#202c33] bg-[#202c33]/30">
          <h2 className="text-lg font-bold text-[#e9edef] mb-3">🛡️ Secure Chats</h2>
          <div className="flex gap-2">
            <input value={newChannelName} onChange={e => setNewChannelName(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleCreateChannel()} placeholder="New group name..." className="flex-1 bg-[#2a3942] text-[#e9edef] px-3 py-2 rounded-lg text-sm outline-none focus:ring-1 focus:ring-[#00a884]" />
            <button onClick={handleCreateChannel} className="bg-[#00a884] hover:bg-[#06cf9c] text-white px-4 rounded-lg text-sm font-bold transition-colors">+</button>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto">
          {channels.map(ch => (
            <div key={ch.id} onClick={() => loadMessages(ch)} className={`p-4 border-b border-[#202c33]/50 cursor-pointer hover:bg-[#202c33] transition-colors ${activeChannel?.id === ch.id ? 'bg-[#2a3942]' : ''}`}>
              <p className="text-[#e9edef] font-medium truncate flex items-center gap-2">
                <span className="w-8 h-8 rounded-full bg-[#00a884]/20 flex items-center justify-center text-sm">👥</span>
                {ch.name}
              </p>
              <p className="text-xs text-[#8696a0] mt-1 ml-10 truncate">End-to-End Encrypted</p>
            </div>
          ))}
          {channels.length === 0 && <p className="p-8 text-center text-[#8696a0] text-sm">Create a group to start.</p>}
        </div>
      </div>

      <div className="flex-1 flex flex-col bg-[#0b141a]">
        {activeChannel ? (
          <>
            <div className="p-4 border-b border-[#202c33] bg-[#111b21] flex justify-between items-center">
              <div>
                <h3 className="text-[#e9edef] font-bold text-lg">{activeChannel.name}</h3>
                <p className="text-xs text-[#8696a0] flex items-center gap-2">
                  {wsStatus === 'connected' && <><span className="w-2 h-2 rounded-full bg-[#00a884] animate-pulse"></span> Connected • E2EE</>}
                  {wsStatus === 'connecting' && <><span className="w-2 h-2 rounded-full bg-yellow-500 animate-pulse"></span> Connecting...</>}
                  {wsStatus === 'disconnected' && <><span className="w-2 h-2 rounded-full bg-red-500"></span> Offline</>}
                </p>
              </div>
              <div className="flex items-center gap-4">
                {/* Phase 11: Call Button */}
                <button onClick={startCall} className="text-2xl text-[#00a884] hover:text-[#06cf9c] transition-colors" title="Start Video Call">
                  📞
                </button>
                <span className="text-2xl">🔒</span>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-4 bg-[#0b141a]">
              {messages.map(m => {
                const isMe = m.sender_id === ((user as any)?.id || 'me');
                return (
                  <div key={m.id} className={`flex ${isMe ? 'justify-end' : 'justify-start'} group relative`}>
                    
                    <div className={`absolute top-0 ${isMe ? 'right-full mr-2' : 'left-full ml-2'} hidden group-hover:flex bg-[#111b21] rounded-lg shadow-lg p-1 gap-1 z-10 border border-[#2a3942]`}>
                      {isMe && m.type === 'text' && (
                        <button onClick={() => startEdit(m)} className="p-1.5 text-xs text-[#8696a0] hover:text-[#e9edef] transition-colors" title="Edit">✏️</button>
                      )}
                      {isMe && (
                        <button onClick={() => handleDelete(m.id)} className="p-1.5 text-xs text-[#8696a0] hover:text-red-500 transition-colors" title="Delete">🗑️</button>
                      )}
                      <button onClick={() => setReplyingTo(m)} className="p-1.5 text-xs text-[#8696a0] hover:text-[#e9edef] transition-colors" title="Reply">↩️</button>
                    </div>

                    <div className={`max-w-[75%] px-4 py-2 rounded-2xl shadow-sm ${isMe ? 'bg-[#005c4b] text-[#e9edef] rounded-br-none' : 'bg-[#202c33] text-[#e9edef] rounded-bl-none'}`}>
                      
                      {m.reply_to_id && (
                        <div className="mb-1 px-2 py-1 bg-black/20 rounded border-l-2 border-[#00a884] text-xs text-[#8696a0] truncate">
                          ↩️ {m.reply_preview || 'Replied message'}
                        </div>
                      )}

                      {m.type === 'file' ? (
                        <div>
                          {m.blob_url && m.file_type?.startsWith('image/') ? (
                            <img src={m.blob_url} alt={m.file_name} className="max-w-full max-h-64 rounded-lg mb-2 cursor-pointer hover:opacity-90" onClick={() => window.open(m.blob_url)} />
                          ) : (
                            <div className="flex items-center gap-3 p-2 bg-black/20 rounded-lg mb-2">
                              <span className="text-3xl">📎</span>
                              <div>
                                <p className="text-sm font-medium truncate max-w-[200px]">{m.file_name}</p>
                                <p className="text-xs text-[#8696a0]">Encrypted File</p>
                              </div>
                            </div>
                          )}
                        </div>
                      ) : (
                        <p className="text-[15px] whitespace-pre-wrap break-words leading-relaxed">{m.plaintext}</p>
                      )}

                      <div className="flex justify-end items-center gap-1 mt-1 -mb-1">
                        {m.edited && <span className="text-[10px] text-[#8696a0] italic mr-1">edited</span>}
                        <span className="text-[10px] text-[#8696a0]">
                          {new Date(m.created_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                        </span>
                        {isMe && (
                          <span className="text-xs ml-1">
                            {m.status === 'sending' && <span className="text-[#8696a0]">🕒</span>}
                            {m.status === 'sent' && <span className="text-[#53bdeb]">✓</span>}
                            {m.status === 'failed' && <span className="text-red-500">❌</span>}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
              <div ref={messagesEndRef} />
            </div>

            {replyingTo && (
              <div className="px-4 py-2 bg-[#202c33] border-l-4 border-[#00a884] flex justify-between items-center">
                <p className="text-xs text-[#8696a0] truncate">↩️ Replying to: <span className="text-[#e9edef]">{replyingTo.plaintext || 'Message'}</span></p>
                <button onClick={() => setReplyingTo(null)} className="text-[#8696a0] hover:text-[#e9edef] ml-4">✕</button>
              </div>
            )}
            {editingMessage && (
              <div className="px-4 py-2 bg-[#2a3942] border-l-4 border-yellow-500 flex justify-between items-center">
                <p className="text-xs text-[#e9edef] truncate">✏️ Editing message...</p>
                <button onClick={cancelEdit} className="text-[#8696a0] hover:text-[#e9edef] ml-4">✕</button>
              </div>
            )}

            <div className="p-4 border-t border-[#202c33] bg-[#202c33]/30 relative">
              {showEmojis && (
                <div className="absolute bottom-20 left-4 bg-[#111b21] p-3 rounded-xl shadow-2xl grid grid-cols-6 gap-2 border border-[#2a3942] z-10">
                  {EMOJIS.map(e => (<button key={e} onClick={() => { setInput(prev => prev + e); setShowEmojis(false); }} className="text-2xl hover:bg-[#2a3942] p-2 rounded-lg transition-colors">{e}</button>))}
                </div>
              )}
              <div className="flex items-center gap-3 bg-[#2a3942] rounded-3xl px-4 py-2">
                <button onClick={() => setShowEmojis(!showEmojis)} className="text-2xl text-[#8696a0] hover:text-[#e9edef] transition-colors">😊</button>
                <input type="file" ref={fileInputRef} onChange={handleFileSelect} className="hidden" accept="image/*,application/pdf,.txt,.doc,.docx" />
                <button onClick={() => fileInputRef.current?.click()} className="text-2xl text-[#8696a0] hover:text-[#e9edef] transition-colors rotate-45">📎</button>
                <input 
                  value={input} 
                  onChange={e => setInput(e.target.value)} 
                  onKeyDown={e => e.key === 'Enter' && !e.shiftKey && handleSend()}
                  placeholder={editingMessage ? "Edit message..." : "Type a secure message..."} 
                  className="flex-1 bg-transparent text-[#e9edef] px-2 py-1 outline-none placeholder-[#8696a0]" 
                  autoFocus={!!editingMessage}
                />
                <button onClick={handleSend} disabled={!input.trim()} className="w-10 h-10 flex items-center justify-center rounded-full bg-[#00a884] hover:bg-[#06cf9c] text-white font-bold transition-all disabled:opacity-50 disabled:cursor-not-allowed">
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="w-5 h-5 ml-0.5"><path d="M3.478 2.404a.75.75 0 0 0-.926.941l2.432 7.905H13.5a.75.75 0 0 1 0 1.5H4.984l-2.432 7.905a.75.75 0 0 0 .926.94 60.519 60.519 0 0 0 18.445-8.986.75.75 0 0 0 0-1.218A60.517 60.517 0 0 0 3.478 2.404Z" /></svg>
                </button>
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-[#8696a0] bg-[#0b141a]">
            <div className="text-center p-8">
              <div className="text-7xl mb-6 opacity-50">🛡️</div>
              <h2 className="text-2xl font-bold text-[#e9edef] mb-2">Emergency Delivery Chat</h2>
              <p className="max-w-sm mx-auto text-sm">Select a secure channel from the sidebar or create a new one to start messaging. All messages and files are end-to-end encrypted.</p>
            </div>
          </div>
        )}
      </div>

      {/* Phase 11: Call Overlay */}
      <CallOverlay 
        localStream={localStream} 
        remoteStream={remoteStream} 
        callState={callState} 
        pendingOffer={pendingOffer}
        onAccept={acceptCall}
        onHangUp={() => hangUp()}
      />
    </div>
  );
}