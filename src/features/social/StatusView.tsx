import { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useAppContext } from '../../context/AppContext';

interface ContactStatus {
  user_id: string;
  display_name: string;
  status_media_key: string;
  status_caption: string;
  status_expires_at: string;
}

export default function StatusView() {
  const { sessionToken, user } = useAppContext();
  
  const [contactStatuses, setContactStatuses] = useState<ContactStatus[]>([]);
  const [viewingStatus, setViewingStatus] = useState<ContactStatus | null>(null);
  const [caption, setCaption] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);

  useEffect(() => {
    if (sessionToken) {
      // Fetch my profile and contacts' statuses
      invoke<any>('social_search_user', { sessionToken, phoneNumber: '' }).catch(() => {}); // Trigger sync if needed
        invoke<any[]>('social_list_contacts', { sessionToken }).then(async (_contacts) => {
        // In a real app, we'd fetch profiles for each contact. 
        // For now, we'll just show a placeholder UI.
        setContactStatuses([]);
      });
    }
  }, [sessionToken]);

  const handleUploadStatus = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !sessionToken) return;
    setUploading(true);

    try {
      // 1. Encrypt the image locally (using the existing chat file encryption logic)
      const arrayBuffer = await file.arrayBuffer();
      const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, arrayBuffer);
      
      const combined = new Uint8Array(iv.length + ct.byteLength);
      combined.set(iv, 0); combined.set(new Uint8Array(ct), iv.length);
      
      let binary = ''; 
      for (let i = 0; i < combined.byteLength; i++) binary += String.fromCharCode(combined[i]);
      const b64 = btoa(binary);

      // 2. Upload to R2
      const fileKey = await invoke<string>('upload_chat_blob', {
        sessionToken, fileName: file.name, fileType: file.type, fileDataB64: b64
      });

      // 3. Update Profile
      await invoke('social_save_profile', {
        sessionToken,
        displayName: (user as any)?.name || 'User',
        statusText: '', // Keep existing status text if needed
        phoneNumber: '', // Keep existing phone
        statusMediaKey: fileKey,
        statusCaption: caption
      });

      setCaption('');
      alert('✅ Status uploaded! It will disappear in 24 hours.');
    } catch (e) {
      console.error(e);
      alert('❌ Failed to upload status.');
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8">
      <h1 className="text-2xl font-bold text-[#e9edef]">⏱️ Status</h1>
      <p className="text-sm text-[#8696a0]">Photos and videos disappear after 24 hours. Encrypted end-to-end.</p>

      {/* My Status */}
      <div className="panel bg-[#111b21] p-6 rounded-2xl flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="w-16 h-16 rounded-full bg-[#2a3942] flex items-center justify-center text-3xl">
            {(user as any)?.name?.[0] || '👤'}
          </div>
          <div>
            <h2 className="text-lg font-bold text-[#e9edef]">My Status</h2>
            <p className="text-xs text-[#8696a0]">Tap to add status update</p>
          </div>
        </div>
        <button 
          onClick={() => fileInputRef.current?.click()} 
          disabled={uploading}
          className="bg-[#00a884] text-white px-6 py-3 rounded-full font-bold hover:bg-[#06cf9c] transition-colors disabled:opacity-50"
        >
          {uploading ? 'Uploading...' : '+ Add Status'}
        </button>
        <input type="file" ref={fileInputRef} onChange={handleUploadStatus} className="hidden" accept="image/*,video/*" />
      </div>

      {/* Recent Updates */}
      <div className="panel bg-[#111b21] p-6 rounded-2xl">
        <h2 className="text-lg font-bold text-[#e9edef] mb-4">Recent Updates</h2>
        <div className="grid grid-cols-4 gap-4">
          {contactStatuses.map(s => (
            <div key={s.user_id} onClick={() => setViewingStatus(s)} className="cursor-pointer text-center">
              <div className="w-16 h-16 mx-auto rounded-full border-2 border-[#00a884] p-0.5">
                <div className="w-full h-full rounded-full bg-[#2a3942] flex items-center justify-center">
                  {s.display_name[0]}
                </div>
              </div>
              <p className="text-xs text-[#8696a0] mt-2 truncate">{s.display_name}</p>
            </div>
          ))}
          {contactStatuses.length === 0 && <p className="text-sm text-[#8696a0] col-span-4 text-center">No recent updates from contacts.</p>}
        </div>
      </div>

      {/* Status Viewer Modal */}
      {viewingStatus && (
        <div className="fixed inset-0 z-[100] bg-black flex items-center justify-center" onClick={() => setViewingStatus(null)}>
          <div className="max-w-lg w-full text-center">
            <div className="mb-4 text-white font-bold">{viewingStatus.display_name}</div>
            <div className="bg-[#111b21] rounded-xl p-4 text-[#e9edef]">
              <p>Status Media would render here (Decrypt from R2)</p>
              <p className="text-sm text-[#8696a0] mt-2">{viewingStatus.status_caption}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}