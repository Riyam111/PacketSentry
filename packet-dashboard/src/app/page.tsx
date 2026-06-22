"use client";

import React, { useState, useEffect, useRef } from 'react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { Activity, Server, Database, Globe, Zap, Network, ShieldAlert, Lock, Download } from 'lucide-react';

const COLORS = ['#3b82f6', '#10b981', '#8b5cf6', '#f59e0b', '#ef4444', '#06b6d4'];

export default function Dashboard() {
  const [isConnected, setIsConnected] = useState(false);
  const [isAutoScroll, setIsAutoScroll] = useState(true);
  const [data, setData] = useState({
    system: { active_connections: 0, total_connections: 0, classified_connections: 0, unknown_connections: 0, total_packets: 0, total_bytes: 0, classification_rate: 0 },
    applications: [] as any[],
    domains: [] as any[],
    workers: [] as any[],
    recent_flows: [] as any[]
  });

  const flowsContainerRef = useRef<HTMLDivElement>(null);
  const flowsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isAutoScroll) {
      flowsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [data.recent_flows, isAutoScroll]);

  const handleScroll = () => {
    if (!flowsContainerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = flowsContainerRef.current;
    const atBottom = scrollHeight - scrollTop - clientHeight < 30;
    setIsAutoScroll(atBottom);
  };

  useEffect(() => {
    const fetchLiveData = async () => {
      try {
        const res = await fetch('/api/data');
        if (res.ok) {
          const payload = await res.json();
          setData(payload);
          setIsConnected(true);
        } else {
          setIsConnected(false);
        }
      } catch (err) {
        setIsConnected(false);
      }
    };

    const interval = setInterval(fetchLiveData, 1000);
    return () => clearInterval(interval);
  }, []);

  const formatBytes = (bytes: number) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // --- NEW: CSV EXPORT FUNCTION ---
  const handleExportCSV = () => {
    let csv = "--- PACKETSENTRY DPI REPORT ---\n\n";

    csv += "SYSTEM METRICS\n";
    csv += `Total Packets,${data.system.total_packets || 0}\n`;
    csv += `Total Bytes,${data.system.total_bytes || 0}\n`;
    csv += `Total Connections Intercepted,${data.system.total_connections || 0}\n`;
    csv += `Classification Rate,${(data.system.classification_rate || 0).toFixed(1)}%\n\n`;

    csv += "APPLICATIONS DETECTED\n";
    csv += "Application,Bytes,Packets,Connections\n";
    data.applications.forEach(app => {
        csv += `${app.name},${app.bytes},${app.packets},${app.connections}\n`;
    });
    csv += "\n";

    csv += "DOMAINS (SNI) DETECTED\n";
    csv += "Domain,Connections\n";
    data.domains.forEach(d => {
        if (d.domain && d.domain.trim() !== "") {
            csv += `${d.domain},${d.connections}\n`;
        }
    });
    csv += "\n";

    csv += "RECENT NETWORK FLOWS\n";
    csv += "Time,Source IP,Destination IP,Application,Domain\n";
    data.recent_flows.forEach(flow => {
        const time = new Date((flow.timestamp || 0) * 1000).toLocaleTimeString([], {hour12: false});
        csv += `${time},${flow.src_ip},${flow.dst_ip},${flow.application},${flow.domain || 'encrypted'}\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    
    // Names the file with the current date/time
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    link.setAttribute("download", `PacketSentry_Report_${timestamp}.csv`);
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };
  // --------------------------------

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 p-6 font-sans">
      <div className="flex justify-between items-center mb-8 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-600/20 rounded-lg">
            <Activity className="text-blue-500 w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">PacketSentry DPI</h1>
            <p className="text-sm text-slate-400">Deep Packet Inspection Engine v2.0</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          
          {/* NEW EXPORT BUTTON */}
          <button 
            onClick={handleExportCSV}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg shadow-lg transition-colors text-sm font-medium"
          >
            <Download className="w-4 h-4" /> Export CSV
          </button>

          <div className="flex items-center gap-2 px-4 py-2 bg-slate-900 border border-slate-800 rounded-lg shadow-inner">
            <div className={`w-2.5 h-2.5 rounded-full ${isConnected ? 'bg-emerald-500 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]' : 'bg-red-500'}`} />
            <span className="text-sm font-medium">{isConnected ? 'Engine Connected' : 'Awaiting C++ Engine...'}</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
        <MetricCard title="Total Packets" value={(data.system.total_packets || 0).toLocaleString()} icon={<Zap />} color="text-amber-500" bg="bg-amber-500/10" />
        <MetricCard title="Bandwidth Processed" value={formatBytes(data.system.total_bytes)} icon={<Database />} color="text-blue-500" bg="bg-blue-500/10" />
        <MetricCard title="Active Flows" value={data.system.active_connections || 0} subtitle={`${data.system.total_connections || 0} Total Intercepted`} icon={<Network />} color="text-emerald-500" bg="bg-emerald-500/10" />
        <MetricCard title="Classification Rate" value={`${(data.system.classification_rate || 0).toFixed(1)}%`} subtitle={`${data.system.classified_connections || 0} apps identified`} icon={<ShieldAlert />} color="text-purple-500" bg="bg-purple-500/10" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
          <h2 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
            <Globe className="w-5 h-5 text-blue-400" /> Application Distribution (Bytes)
          </h2>
          <div className="h-64">
            {data.applications && data.applications.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={data.applications} cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="bytes" nameKey="name">
                    {data.applications.map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />)}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }} itemStyle={{ color: '#e2e8f0' }} formatter={(value: any) => formatBytes(value)} />
                </PieChart>
              </ResponsiveContainer>
            ) : <div className="flex h-full items-center justify-center text-slate-500 border-2 border-dashed border-slate-800 rounded-lg">Awaiting payload data...</div>}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
          <h2 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
            <Server className="w-5 h-5 text-purple-400" /> Top Domains Detected
          </h2>
          <div className="h-64">
            {data.domains && data.domains.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.domains.filter(d => d.domain && d.domain.trim() !== "").sort((a,b) => b.connections - a.connections).slice(0, 5)} layout="vertical" margin={{ top: 0, right: 0, left: 40, bottom: 0 }}>
                  <XAxis type="number" hide />
                  <YAxis dataKey="domain" type="category" axisLine={false} tickLine={false} tick={{fill: '#94a3b8', fontSize: 12}} width={140} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }} cursor={false} />
                  <Bar dataKey="connections" fill="#3b82f6" radius={[0, 4, 4, 0]} barSize={24}>
                    {data.domains.map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : <div className="flex h-full items-center justify-center text-slate-500 border-2 border-dashed border-slate-800 rounded-lg">Awaiting SNI extraction...</div>}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 lg:col-span-1 shadow-lg">
          <h2 className="text-lg font-semibold text-white mb-4">C++ Worker Load Balancing</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-slate-400 uppercase bg-slate-950/50">
                <tr><th className="px-4 py-3">Thread</th><th className="px-4 py-3">Packets</th><th className="px-4 py-3">Queue</th><th className="px-4 py-3">Classified</th></tr>
              </thead>
              <tbody>
                {data.workers && data.workers.map((w) => (
                  <tr key={w.id} className="border-b border-slate-800 hover:bg-slate-800/50 transition-colors">
                    <td className="px-4 py-3 font-medium text-blue-400">FP_{w.id}</td>
                    <td className="px-4 py-3">{w.packets_processed || 0}</td>
                    <td className="px-4 py-3"><span className={`px-2 py-1 rounded text-xs font-medium ${w.queue_length > 50 ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}`}>{w.queue_length || 0}</span></td>
                    <td className="px-4 py-3">{w.classifications || 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="bg-[#0a0a0a] border border-slate-800 rounded-xl p-6 lg:col-span-2 flex flex-col h-80 shadow-lg relative">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-semibold text-slate-300 font-mono flex items-center gap-2">
              <div className={`w-2 h-4 ${isConnected ? 'bg-emerald-500 animate-pulse' : 'bg-slate-600'}`}></div> 
              Live Application Flows
            </h2>
            {!isAutoScroll && (
              <span className="text-xs font-medium text-amber-500 bg-amber-500/10 px-2 py-1 rounded flex items-center gap-1">
                <Lock className="w-3 h-3" /> Scroll Paused
              </span>
            )}
          </div>
          
          <div 
            ref={flowsContainerRef}
            onScroll={handleScroll}
            className="flex-1 overflow-y-auto font-mono text-xs space-y-2 pr-2 custom-scrollbar"
          >
            {data.recent_flows && data.recent_flows.map((flow, i) => (
              <div key={i} className="flex gap-4 items-center p-2 rounded bg-slate-900/50 hover:bg-slate-800 border-l-2 border-slate-700 hover:border-blue-500 transition-all">
                <span className="text-slate-500 w-16 shrink-0">{new Date((flow.timestamp || 0) * 1000).toLocaleTimeString([], {hour12: false})}</span>
                <span className="text-emerald-400 w-28 truncate">{flow.src_ip || ''}</span><span className="text-slate-600">→</span>
                <span className="text-amber-400 w-28 truncate">{flow.dst_ip || ''}</span>
                <span className="text-purple-400 w-24 font-bold">{flow.application || ''}</span>
                <span className="text-slate-400 flex-1 truncate">{flow.domain || '<encrypted payload>'}</span>
              </div>
            ))}
            <div ref={flowsEndRef} />
          </div>
        </div>

      </div>
    </div>
  );
}

function MetricCard({ title, value, subtitle, icon, color, bg }: { title: string, value: string | number, subtitle?: string, icon: React.ReactNode, color: string, bg: string }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex items-start gap-4 shadow-lg hover:border-slate-700 transition-colors">
      <div className={`p-3 rounded-lg ${bg} ${color}`}>{icon}</div>
      <div>
        <p className="text-sm font-medium text-slate-400 mb-1">{title}</p>
        <h3 className="text-2xl font-bold text-white tracking-tight">{value}</h3>
        {subtitle && <p className="text-xs text-slate-500 mt-1">{subtitle}</p>}
      </div>
    </div>
  );
}