import React, { useState, useEffect, useMemo, useCallback } from "react";

// --- ThreatGuard AI React + Tailwind Dashboard ---
export default function DashboardApp() {
  const [urlInput, setUrlInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState("");
  const [scanData, setScanData] = useState(null);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState("threat");
  const [dbStatus, setDbStatus] = useState({ 
    is_cloud_active: false, 
    engine: "sqlite",
    provider: "SQLite (Air-Gapped)",
    fallback: "threat_intel.db",
    air_gapped_mode: true,
    status_reason: "Offline / Air-Gapped",
    latency_ms: 0,
    checked: false
  });
  const [dbModalOpen, setDbModalOpen] = useState(false);
  const [dbPingLoading, setDbPingLoading] = useState(false);
  const [dbPingNotice, setDbPingNotice] = useState("");
  const [threatFeed, setThreatFeed] = useState([]);
  const [stixModalOpen, setStixModalOpen] = useState(false);
  const [stixContent, setStixContent] = useState("");
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [copiedStix, setCopiedStix] = useState(false);

  const presets = [
    { 
      label: "PayPal Phish", 
      tag: "PHISH", 
      tagStyle: "bg-red-500 text-white font-black shadow-sm", 
      btnStyle: "bg-red-950/50 border-red-500/50 hover:bg-red-900/60 hover:border-red-400 text-red-100", 
      url: "http://paypa1-security-verification.update-account.tk/login" 
    },
    { 
      label: "eMudhra 1024b", 
      tag: "eMUDHRA", 
      tagStyle: "bg-amber-400 text-amber-950 font-black shadow-sm", 
      btnStyle: "bg-amber-950/50 border-amber-500/50 hover:bg-amber-900/60 hover:border-amber-400 text-amber-100", 
      url: "https://emudhra-auth-portal.fraud-verify.com" 
    },
    { 
      label: "Job Scam", 
      tag: "SCAM", 
      tagStyle: "bg-orange-500 text-white font-black shadow-sm", 
      btnStyle: "bg-orange-950/50 border-orange-500/50 hover:bg-orange-900/60 hover:border-orange-400 text-orange-100", 
      url: "http://amazon-global-careers-recruit.xyz/apply" 
    },
    { 
      label: "Chase Bank", 
      tag: "SAFE", 
      tagStyle: "bg-emerald-400 text-emerald-950 font-black shadow-sm", 
      btnStyle: "bg-emerald-950/50 border-emerald-500/50 hover:bg-emerald-900/60 hover:border-emerald-400 text-emerald-100", 
      url: "https://chase.com" 
    },
    { 
      label: "Plaintext HTTP", 
      tag: "HTTP", 
      tagStyle: "bg-slate-300 text-slate-950 font-black shadow-sm", 
      btnStyle: "bg-slate-900/60 border-slate-500/50 hover:bg-slate-800/70 hover:border-slate-400 text-slate-100", 
      url: "http://legacy-banking.insecure.test" 
    }
  ];

  const checkDbStatus = useCallback(async (force = false) => {
    setDbPingLoading(true);
    try {
      const res = await fetch(`/api/system/db-status?force_refresh=${force}`);
      const data = await res.json();
      setDbStatus({
        is_cloud_active: !!data.is_cloud_active,
        engine: data.engine || (data.is_cloud_active ? "supabase" : "sqlite"),
        provider: data.provider,
        fallback: data.database_file || "threat_intel.db",
        air_gapped_mode: !data.is_cloud_active,
        air_gap_override: data.air_gap_override,
        status_reason: data.status_reason || "",
        latency_ms: data.latency_ms || 0,
        checked: true
      });
    } catch {
      setDbStatus(prev => ({ ...prev, is_cloud_active: false, engine: "sqlite" }));
    } finally {
      setDbPingLoading(false);
    }
  }, []);

  const toggleAirGapMode = useCallback(async () => {
    setDbPingLoading(true);
    try {
      const res = await fetch("/api/system/toggle-airgap", { method: "POST" });
      const data = await res.json();
      setDbStatus({
        is_cloud_active: !!data.is_cloud_active,
        engine: data.engine || (data.is_cloud_active ? "supabase" : "sqlite"),
        provider: data.provider,
        fallback: data.database_file || "threat_intel.db",
        air_gapped_mode: !data.is_cloud_active,
        air_gap_override: data.air_gap_override,
        status_reason: data.status_reason || "",
        latency_ms: data.latency_ms || 0,
        checked: true
      });
    } finally {
      setDbPingLoading(false);
    }
  }, []);

  useEffect(() => {
    checkDbStatus(true);
    const handleOnline = () => checkDbStatus(true);
    const handleOffline = () => setDbStatus(prev => ({ ...prev, is_cloud_active: false, engine: "sqlite" }));
    window.addEventListener("online", handleOnline);
    window.addEventListener("offline", handleOffline);

    fetch("/api/threats/feed?limit=6")
      .then(res => res.json())
      .then(data => setThreatFeed(data.feed || []))
      .catch(() => {});

    const params = new URLSearchParams(window.location.search);
    const autoUrl = params.get("url");
    if (autoUrl) {
      setUrlInput(autoUrl);
      runAudit(autoUrl);
    }
  }, []);

  const runAudit = useCallback(async (targetUrl) => {
    const query = (targetUrl || urlInput || "https://chase.com").trim();
    setUrlInput(query);
    setLoading(true);
    setError(null);
    setLoadingStep("Validating X.509 cryptography, checking eMudhra key patterns, and sniffing DOM forms...");

    try {
      const resp = await fetch(`/analyze?url=${encodeURIComponent(query)}`);
      if (!resp.ok) {
        const errJson = await resp.json();
        throw new Error(errJson.detail || "Target audit request failed");
      }
      const data = await resp.json();
      setScanData(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [urlInput]);

  const scrollToTab = useCallback((tabKey) => {
    setActiveTab(tabKey);
    setTimeout(() => {
      const el = document.getElementById("inspection-tabs-section");
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }, 60);
  }, []);

  return (
    <div className="flex flex-col min-h-screen bg-cyber-950 text-slate-100 font-sans">
      {/* Header, SearchConsole, Scorecard, InspectionTabs, and Feed components */}
    </div>
  );
}
