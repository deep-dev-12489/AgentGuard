"use client";

import { useState, useCallback, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Shield, Activity, Zap, RefreshCw, AlertCircle } from "lucide-react";
import type { AuditLogEntry, ScanState, AnalysisResponse, Verdict } from "@/types";
import DropZone from "@/components/DropZone";
import ThreatMatrix from "@/components/ThreatMatrix";
import SideDrawer from "@/components/SideDrawer";
import ThemeToggle from "@/components/ThemeToggle";

// ─────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────
const API_BASE = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");

async function getApiErrorMessage(res: Response): Promise<string> {
  try {
    const payload = await res.json();
    const detail = payload?.detail;
    if (typeof detail === "string") return detail;
    if (detail && typeof detail.reason === "string") return detail.reason;
    if (typeof payload?.message === "string") return payload.message;
  } catch {
    // not JSON
  }
  return `Request failed (${res.status}${res.statusText ? `: ${res.statusText}` : ""}).`;
}

function verdictFromResponse(data: AnalysisResponse): Verdict {
  const dec = data.security_decision?.decision;
  if (dec === "BLOCK" || data.status === "BLOCKED") return "BLOCK";
  if (dec === "REVIEW" || data.status === "REVIEW_REQUIRED") return "REVIEW";
  return "ALLOW";
}

function scanStateFromVerdict(v: Verdict): ScanState {
  if (v === "BLOCK") return "result_block";
  if (v === "REVIEW") return "result_review";
  return "result_allow";
}

// ─────────────────────────────────────────
// Navbar
// ─────────────────────────────────────────
function Navbar({ hasError }: { hasError: boolean }) {
  return (
    <header className="sticky top-0 z-30 border-b border-slate-200/80 dark:border-slate-800/70 bg-white/80 dark:bg-slate-950/80 backdrop-blur-xl px-6 py-4 transition-colors duration-300">
      <div className="max-w-5xl mx-auto flex items-center justify-between">
        {/* Logo */}
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-emerald-500/15 to-emerald-600/25 dark:from-emerald-500/20 dark:to-emerald-950/60 border border-emerald-500/30 flex items-center justify-center shadow shadow-emerald-500/10">
            <Shield className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
          </div>
          <div>
            <span className="font-display font-bold text-lg text-slate-900 dark:text-white tracking-tight">AgentGuard</span>
            <span className="ml-2 text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-700 dark:text-emerald-400 font-semibold tracking-wider">
              Command Center
            </span>
          </div>
        </div>

        {/* Right controls: Status indicator + ThemeToggle */}
        <div className="flex items-center gap-3">
          <div
            className={`flex items-center gap-1.5 text-[11px] font-mono px-2.5 py-1 rounded-full border transition-colors ${
              hasError
                ? "border-red-300 dark:border-red-800/50 bg-red-50 dark:bg-red-950/20 text-red-700 dark:text-red-400"
                : "border-emerald-300/80 dark:border-emerald-800/50 bg-emerald-50 dark:bg-emerald-950/20 text-emerald-700 dark:text-emerald-400"
            }`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                hasError ? "bg-red-500" : "bg-emerald-500 dark:bg-emerald-400 animate-pulse"
              }`}
            />
            {hasError ? "Backend Offline" : "System Active"}
          </div>

          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}

// ─────────────────────────────────────────
// Main Page Component
// ─────────────────────────────────────────
export default function CommandCenter() {
  const [scanState, setScanState] = useState<ScanState>("idle");
  const [fileName, setFileName] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<AnalysisResponse | null>(null);
  const [auditLog, setAuditLog] = useState<AuditLogEntry[]>([]);
  const [selectedEntry, setSelectedEntry] = useState<AuditLogEntry | null>(null);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);

  // ── File drop handler ──────────────────
  const handleFileDrop = useCallback(async (file: File) => {
    setFileName(file.name);
    setScanState("scanning");
    setIsUploading(true);
    setBackendError(null);

    const formData = new FormData();
    formData.append("file", file);
    formData.append("user_prompt", "Analyze this document and summarize key findings.");

    try {
      const res = await fetch(`${API_BASE}/api/upload_and_analyze`, {
        method: "POST",
        body: formData,
      });

      if (!res.ok) throw new Error(await getApiErrorMessage(res));

      const data: AnalysisResponse = await res.json();
      const verdict = verdictFromResponse(data);
      const newState = scanStateFromVerdict(verdict);

      setLastResult(data);
      setScanState(newState);
      setBackendError(null);

      const entry: AuditLogEntry = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
        timestamp: new Date().toLocaleTimeString([], {
          hour12: false,
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
        fileName: file.name,
        verdict,
        riskLevel: data.security_decision?.risk_level,
        payload: data,
      };
      setAuditLog((prev) => [...prev, entry]);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Upload failed.";
      setBackendError(msg);
      setScanState("idle");
    } finally {
      setIsUploading(false);
    }
  }, []);

  // ── Text analysis fallback ──────────────
  const handleAnalyzeText = useCallback(
    async (text: string, name: string) => {
      setFileName(name);
      setScanState("scanning");
      setBackendError(null);

      try {
        const res = await fetch(`${API_BASE}/api/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            prompt: "Analyze this document and summarize key findings.",
            document_text: text,
          }),
        });

        if (!res.ok) throw new Error(await getApiErrorMessage(res));

        const data: AnalysisResponse = await res.json();
        const verdict = verdictFromResponse(data);

        setLastResult(data);
        setScanState(scanStateFromVerdict(verdict));

        const entry: AuditLogEntry = {
          id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
          timestamp: new Date().toLocaleTimeString([], {
            hour12: false,
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          }),
          fileName: name,
          verdict,
          riskLevel: data.security_decision?.risk_level,
          payload: data,
        };
        setAuditLog((prev) => [...prev, entry]);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Analysis failed.";
        setBackendError(msg);
        setScanState("idle");
      }
    },
    []
  );

  // ── Reset dropzone ─────────────────────
  const resetScan = useCallback(() => {
    setScanState("idle");
    setFileName(null);
    setLastResult(null);
  }, []);

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col selection:bg-emerald-500/20 selection:text-emerald-900 dark:selection:text-emerald-100 transition-colors duration-300">
      {/* Ambient background glow */}
      <div className="fixed inset-0 pointer-events-none z-0">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[700px] h-[350px] bg-emerald-200/40 dark:bg-emerald-950/30 rounded-full blur-[140px] transition-colors duration-500" />
        <div className="absolute bottom-0 right-0 w-[400px] h-[300px] bg-blue-200/30 dark:bg-blue-950/20 rounded-full blur-[120px] transition-colors duration-500" />
      </div>

      {/* Navbar */}
      <Navbar hasError={!!backendError} />

      {/* Error banner */}
      <AnimatePresence>
        {backendError && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            className="relative z-20 overflow-hidden"
          >
            <div className="bg-red-50 dark:bg-red-950/80 border-b border-red-200 dark:border-red-800/60 px-6 py-3 flex items-center justify-between text-xs text-red-800 dark:text-red-300 font-mono">
              <div className="flex items-center gap-2">
                <AlertCircle className="h-4 w-4 text-red-600 dark:text-red-400 shrink-0" />
                <span>{backendError}</span>
              </div>
              <button
                onClick={() => setBackendError(null)}
                className="text-red-600 dark:text-red-500 hover:text-red-800 dark:hover:text-red-300 transition-colors"
              >
                ✕
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main content */}
      <main className="relative z-10 flex-1 max-w-5xl mx-auto w-full px-6 py-8 space-y-8">

        {/* ── SECTION 1: Scanner Zone ───────── */}
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <h1 className="font-display text-2xl font-bold text-slate-900 dark:text-white tracking-tight">
                Security Scanner
              </h1>
              <p className="text-sm text-slate-600 dark:text-slate-400">
                Deploy any document for zero-trust heuristic analysis
              </p>
            </div>

            {/* Reset button — only shown after a scan */}
            <AnimatePresence>
              {scanState !== "idle" && (
                <motion.button
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.9 }}
                  onClick={resetScan}
                  className="flex items-center gap-1.5 text-xs font-mono text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-700 bg-white dark:bg-slate-900/60 hover:bg-slate-100 dark:hover:bg-slate-900 shadow-sm transition-all"
                >
                  <RefreshCw className="h-3 w-3" />
                  New Scan
                </motion.button>
              )}
            </AnimatePresence>
          </div>

          <DropZone
            scanState={scanState}
            fileName={fileName}
            onFileDrop={handleFileDrop}
            onAnalyzeText={handleAnalyzeText}
            lastResult={lastResult}
          />

          {/* Loading shimmer indicator */}
          {(isUploading || scanState === "scanning") && (
            <div className="flex items-center gap-2 text-[11px] font-mono text-blue-600 dark:text-blue-400">
              <Activity className="h-3.5 w-3.5 animate-pulse" />
              <span>Dispatching to security control plane…</span>
            </div>
          )}
        </section>

        {/* Divider */}
        <div className="h-px bg-gradient-to-r from-transparent via-slate-200 dark:via-slate-800 to-transparent" />

        {/* ── SECTION 2: Threat Matrix ──────── */}
        <section>
          <ThreatMatrix
            logs={auditLog}
            onRowClick={(entry) => setSelectedEntry(entry)}
            selectedId={selectedEntry?.id ?? null}
          />
        </section>
      </main>

      {/* Side drawer */}
      <SideDrawer
        entry={selectedEntry}
        onClose={() => setSelectedEntry(null)}
      />
    </div>
  );
}
