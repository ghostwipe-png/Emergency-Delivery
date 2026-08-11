// src/features/social/SocialView.tsx
import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useAppContext } from '../../context/AppContext';

export default function SocialView() {
  const { sessionToken, user } = useAppContext();
  const [displayName, setDisplayName] = useState((user as any)?.name || '');
  const [status, setStatus] = useState('Hey there! I am using Emergency Delivery.');
  const [phone, setPhone] = useState('');
  const [searchPhone, setSearchPhone] = useState('');
  const [searchResult, setSearchResult] = useState<any>(null);
  const [contacts, setContacts] = useState<any[]>([]);
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (sessionToken) {
            invoke<any[]>('social_list_contacts', { sessionToken }).then(setContacts).catch(console.error);
    }
  }, [sessionToken]);

  const handleSaveProfile = async () => {
    try {
      await invoke('social_save_profile', { sessionToken, displayName, statusText: status, phoneNumber: phone });
      setMessage('✅ Profile saved & synced to global directory!');
    } catch (e: any) {
      setMessage(`❌ ${e}`);
    }
  };

  const handleSearch = async () => {
    setSearchResult(null);
    try {
      const res = await invoke<any>('social_search_user', { sessionToken, phoneNumber: searchPhone });
      if (res?.found) setSearchResult(res.profile);
      else setMessage('❌ User not found. They must have the app and a saved profile.');
    } catch (e: any) {
      setMessage(`❌ ${e}`);
    }
  };

  const handleAddContact = async (userId: string) => {
    try {
      await invoke('social_add_contact', { sessionToken, contactUserId: userId });
      setMessage('✅ Contact added!');
      const updated = await invoke<any[]>('social_list_contacts', { sessionToken });
      setContacts(updated);
    } catch (e: any) {
      setMessage(`❌ ${e}`);
    }
  };

  return (
    <div className="p-8 max-w-2xl mx-auto space-y-8">
      <h1 className="text-2xl font-bold text-[#e9edef]">🌐 Social Layer</h1>
      <p className="text-sm text-[#8696a0]">Standalone module. Does not affect Emergency Deliveries.</p>

      {message && <div className="p-3 rounded-lg bg-[#202c33] text-sm text-[#e9edef]">{message}</div>}

      {/* Profile Setup */}
      <div className="panel bg-[#111b21] p-6 rounded-2xl space-y-4">
        <h2 className="text-lg font-bold text-[#e9edef]">My Public Profile</h2>
        <input value={displayName} onChange={e => setDisplayName(e.target.value)} placeholder="Display Name" className="w-full bg-[#202c33] p-3 rounded-xl text-[#e9edef] outline-none" />
        <input value={status} onChange={e => setStatus(e.target.value)} placeholder="Status" className="w-full bg-[#202c33] p-3 rounded-xl text-[#e9edef] outline-none" />
        <input value={phone} onChange={e => setPhone(e.target.value)} placeholder="Phone Number (for discovery)" className="w-full bg-[#202c33] p-3 rounded-xl text-[#e9edef] outline-none" />
        <button onClick={handleSaveProfile} className="w-full bg-[#00a884] text-white py-3 rounded-xl font-bold">Save & Sync Profile</button>
      </div>

      {/* Search */}
      <div className="panel bg-[#111b21] p-6 rounded-2xl space-y-4">
        <h2 className="text-lg font-bold text-[#e9edef]">Find Users</h2>
        <div className="flex gap-2">
          <input value={searchPhone} onChange={e => setSearchPhone(e.target.value)} placeholder="Search by phone number..." className="flex-1 bg-[#202c33] p-3 rounded-xl text-[#e9edef] outline-none" />
          <button onClick={handleSearch} className="bg-[#00a884] text-white px-6 rounded-xl font-bold">Search</button>
        </div>
        {searchResult && (
          <div className="p-4 bg-[#202c33] rounded-xl flex justify-between items-center">
            <div>
              <p className="font-bold text-[#e9edef]">{searchResult.display_name}</p>
              <p className="text-xs text-[#8696a0]">{searchResult.status_text}</p>
            </div>
            <button onClick={() => handleAddContact(searchResult.user_id)} className="bg-[#2a3942] text-[#e9edef] px-4 py-2 rounded-lg text-sm">Add Contact</button>
          </div>
        )}
      </div>

      {/* Contacts */}
      <div className="panel bg-[#111b21] p-6 rounded-2xl">
        <h2 className="text-lg font-bold text-[#e9edef] mb-4">My Contacts ({contacts.length})</h2>
        {contacts.map(c => (
          <div key={c.id} className="p-2 border-b border-[#202c33] text-sm text-[#8696a0]">
            User ID: {c.contact_user_id}
          </div>
        ))}
      </div>
    </div>
  );
}