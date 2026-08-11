import { useEffect, useState } from "react";
import { useAppContext } from "../context/AppContext";
import { api, errorMessage } from "../services/api";
import type { Analytics } from "../types";
import { 
  PieChart, Pie, Cell, 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend
} from 'recharts';

function fmtBytes(n: number): string {
  if (n >= 1024 * 1024 * 1024) return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

const COLORS = {
  email: '#00a884',
  sms: '#53bdeb',
  file: '#e9edef',
  text: '#8696a0',
  success: '#00a884',
  failed: '#f87171',
  pending: '#fbbf24',
  cancelled: '#8696a0',
};

export default function AnalyticsView() {
  const { sessionToken } = useAppContext();
  const [data, setData] = useState<Analytics | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!sessionToken) return;
    api
      .getAnalytics(sessionToken)
      .then(setData)
      .catch((e) => setError(errorMessage(e)));
  }, [sessionToken]);

  if (error) return <p className="p-6 text-sm text-red-400">{error}</p>;
  if (!data) return <p className="p-6 text-sm text-[#8696a0] animate-pulse">Crunching the numbers…</p>;

  const s = data.summary;
  // Sort daily data chronologically for the bar chart
  const days = [...data.daily].sort((a, b) => a.day.localeCompare(b.day));
  
  const successRate = s.total > 0 ? Math.round((s.delivered / s.total) * 100) : 0;

  const channelData = [
    { name: 'Email', value: s.emails, color: COLORS.email },
    { name: 'SMS', value: s.sms, color: COLORS.sms },
  ].filter(d => d.value > 0);

  const contentData = [
    { name: 'Files', value: s.files, color: COLORS.file },
    { name: 'Texts', value: s.texts, color: COLORS.text },
  ].filter(d => d.value > 0);

  const statusData = [
    { name: 'Delivered', value: s.delivered, color: COLORS.success },
    { name: 'Pending', value: s.pending, color: COLORS.pending },
    { name: 'Cancelled', value: s.cancelled, color: COLORS.cancelled },
    { name: 'Failed', value: s.failed, color: COLORS.failed },
  ].filter(d => d.value > 0);

  return (
    <div className="fade-in mx-auto max-w-5xl space-y-6 p-6">
      <header>
        <h1 className="text-2xl font-bold text-[#e9edef]">Analytics & Insights</h1>
        <p className="text-sm text-[#8696a0] mt-1">Comprehensive overview of your secure delivery activity.</p>
      </header>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="panel-2 bg-[#202c33] rounded-xl p-5">
          <p className="text-xs text-[#8696a0] uppercase tracking-wider mb-1">Total Deliveries</p>
          <p className="text-3xl font-bold text-[#e9edef]">{s.total}</p>
          <p className="text-xs text-[#8696a0] mt-2">
            <span className="text-[#00a884]">{s.delivered} sent</span> • {s.pending} pending
          </p>
        </div>

        <div className="panel-2 bg-[#202c33] rounded-xl p-5">
          <p className="text-xs text-[#8696a0] uppercase tracking-wider mb-1">Success Rate</p>
          <p className="text-3xl font-bold text-[#00a884]">{successRate}%</p>
          <p className="text-xs text-[#8696a0] mt-2">
            {s.failed > 0 && <span className="text-red-400">{s.failed} failed</span>}
            {s.failed === 0 && 'Flawless delivery record'}
          </p>
        </div>

        <div className="panel-2 bg-[#202c33] rounded-xl p-5">
          <p className="text-xs text-[#8696a0] uppercase tracking-wider mb-1">Data Transferred</p>
          <p className="text-3xl font-bold text-[#53bdeb]">{fmtBytes(s.bytes_sent)}</p>
          <p className="text-xs text-[#8696a0] mt-2">Encrypted end-to-end</p>
        </div>

        <div className="panel-2 bg-[#202c33] rounded-xl p-5">
          <p className="text-xs text-[#8696a0] uppercase tracking-wider mb-1">Channel Split</p>
          <p className="text-3xl font-bold text-[#e9edef]">
            {s.emails} <span className="text-sm font-normal text-[#8696a0]">/ {s.sms}</span>
          </p>
          <p className="text-xs text-[#8696a0] mt-2">Emails vs SMS</p>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Channel Distribution */}
        <div className="panel-2 bg-[#202c33] rounded-2xl p-6">
          <h3 className="text-sm font-bold text-[#e9edef] mb-4 uppercase tracking-wider">Channels</h3>
          {channelData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={channelData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={4} dataKey="value">
                  {channelData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#111b21', border: '1px solid #2a3942', borderRadius: '8px', color: '#e9edef' }} />
                <Legend wrapperStyle={{ color: '#8696a0', fontSize: '12px' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-[#8696a0] text-sm text-center mt-12">No channel data yet.</p>
          )}
        </div>

        {/* Content Distribution */}
        <div className="panel-2 bg-[#202c33] rounded-2xl p-6">
          <h3 className="text-sm font-bold text-[#e9edef] mb-4 uppercase tracking-wider">Content Types</h3>
          {contentData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={contentData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={4} dataKey="value">
                  {contentData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#111b21', border: '1px solid #2a3942', borderRadius: '8px', color: '#e9edef' }} />
                <Legend wrapperStyle={{ color: '#8696a0', fontSize: '12px' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-[#8696a0] text-sm text-center mt-12">No content data yet.</p>
          )}
        </div>

        {/* Status Breakdown */}
        <div className="panel-2 bg-[#202c33] rounded-2xl p-6">
          <h3 className="text-sm font-bold text-[#e9edef] mb-4 uppercase tracking-wider">Status Breakdown</h3>
          {statusData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={statusData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={4} dataKey="value">
                  {statusData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="none" />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#111b21', border: '1px solid #2a3942', borderRadius: '8px', color: '#e9edef' }} />
                <Legend wrapperStyle={{ color: '#8696a0', fontSize: '12px' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-[#8696a0] text-sm text-center mt-12">No status data yet.</p>
          )}
        </div>
      </div>

      {/* Daily Activity Bar Chart */}
      <div className="panel-2 bg-[#202c33] rounded-2xl p-6">
        <h3 className="text-sm font-bold text-[#e9edef] mb-4 uppercase tracking-wider">Daily Activity (Last 30 Days)</h3>
        {days.length > 0 ? (
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={days} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a3942" vertical={false} />
              <XAxis 
                dataKey="day" 
                tick={{ fill: '#8696a0', fontSize: 11 }} 
                tickFormatter={(val) => val.slice(5)} // Show MM-DD
                axisLine={{ stroke: '#2a3942' }}
                tickLine={false}
              />
              <YAxis 
                tick={{ fill: '#8696a0', fontSize: 11 }} 
                axisLine={{ stroke: '#2a3942' }}
                tickLine={false}
                allowDecimals={false}
              />
              <Tooltip 
                cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                contentStyle={{ backgroundColor: '#111b21', border: '1px solid #2a3942', borderRadius: '8px', color: '#e9edef' }}
                labelFormatter={(label) => `Date: ${label}`}
              />
              <Bar dataKey="count" fill="#00a884" radius={[4, 4, 0, 0]} name="Deliveries" />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <p className="text-[#8696a0] text-sm text-center mt-12">No daily activity recorded yet.</p>
        )}
      </div>
    </div>
  );
}