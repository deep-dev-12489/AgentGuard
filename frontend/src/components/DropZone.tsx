"use client";

import { useCallback, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Upload, Shield, FileText, AlertCircle } from "lucide-react";
import dynamic from "next/dynamic";
import type { ScanState, AnalysisResponse } from "@/types";

// Dynamically import Scanner3D to avoid SSR issues with WebGL
const Scanner3D = dynamic(() => import("@/components/Scanner3D"), { ssr: false });

interface DropZoneProps {
  scanState: ScanState;
  fileName: string | null;
  onFileDrop: (file: File) => void;
  onAnalyzeText: (text: string, name: string) => void;
  lastResult: AnalysisResponse | null;
}

// ──────────────────────────────────────────────
// Idle overlay — shown when scanState === "idle"
// ──────────────────────────────────────────────
function IdleOverlay({ isDragging }: { isDragging: boolean }) {
  return (
    <motion.div
      key="idle"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0, y: -10 }}
      transition={{ duration: 0.4 }}
      className="absolute inset-0 flex flex-col items-center justify-center gap-6 px-8 pointer-events-none select-none"
    >
      {/* Icon halo */}
      <div className="relative">
        <motion.div
          className="absolute inset-0 rounded-full bg-emerald-500/10"
          animate={{ scale: isDragging ? [1, 1.5, 1] : 1, opacity: isDragging ? [0.5, 0, 0.5] : 0 }}
          transition={{ duration: 1.2, repeat: Infinity }}
        />
        <div
          className={`h-20 w-20 rounded-full border flex items-center justify-center transition-colors duration-300 ${
            isDragging
              ? "border-emerald-400/60 bg-emerald-500/10 shadow-lg shadow-emerald-500/20"
              : "border-slate-200 bg-white/80 dark:border-slate-700/80 dark:bg-slate-900/60 shadow-sm"
          }`}
        >
          <Upload
            className={`h-8 w-8 transition-colors duration-300 ${
              isDragging ? "text-emerald-500 dark:text-emerald-400" : "text-slate-400 dark:text-slate-500"
            }`}
          />
        </div>
      </div>

      <div className="text-center space-y-2">
        <p className="font-display text-xl font-semibold text-slate-800 dark:text-slate-200 tracking-tight">
          {isDragging ? "Release to Deploy Document" : "Deploy Document for Security Analysis"}
        </p>
        <p className="text-sm text-slate-500 dark:text-slate-400 font-mono">
          Drag & drop a PDF · or click to browse
        </p>
      </div>

      <div className="flex items-center gap-6 text-[11px] font-mono text-slate-500 dark:text-slate-500">
        <span className="flex items-center gap-1.5">
          <Shield className="h-3 w-3 text-emerald-600 dark:text-emerald-500/70" />
          Zero-Trust Scan
        </span>
        <span className="flex items-center gap-1.5">
          <FileText className="h-3 w-3 text-blue-600 dark:text-blue-500/70" />
          PDF / TXT
        </span>
        <span className="flex items-center gap-1.5">
          <AlertCircle className="h-3 w-3 text-amber-600 dark:text-amber-500/70" />
          Heuristic Analysis
        </span>
      </div>
    </motion.div>
  );
}

// ──────────────────────────────────────────────
// Status overlay — scanning / result states
// ──────────────────────────────────────────────
function StatusOverlay({
  scanState,
  fileName,
  lastResult,
}: {
  scanState: ScanState;
  fileName: string | null;
  lastResult: AnalysisResponse | null;
}) {
  const isBlock = scanState === "result_block";
  const isAllow = scanState === "result_allow";

  type StatusConfig = { label: string; sub: string; color: string; border: string; glow: string };
  const STATUS_MAP: Record<string, StatusConfig> = {
    scanning: {
      label: "Deep Heuristic Scan",
      sub: "Parsing document · Extracting claims · Evaluating threat vectors",
      color: "text-blue-600 dark:text-blue-400",
      border: "border-blue-300/80 dark:border-blue-500/20",
      glow: "shadow-blue-500/10",
    },
    result_allow: {
      label: "SCAN COMPLETE — ALLOW",
      sub: lastResult?.summary || "Document cleared. No injection vectors detected.",
      color: "text-emerald-700 dark:text-emerald-400",
      border: "border-emerald-300/80 dark:border-emerald-500/20",
      glow: "shadow-emerald-500/15",
    },
    result_block: {
      label: "THREAT DETECTED — BLOCKED",
      sub: lastResult?.security_decision?.reason || lastResult?.summary || "Prompt injection vector intercepted.",
      color: "text-red-700 dark:text-red-400",
      border: "border-red-300/80 dark:border-red-500/20",
      glow: "shadow-red-500/15",
    },
    result_review: {
      label: "REVIEW REQUIRED",
      sub: lastResult?.security_decision?.reason || "Human operator authorization required.",
      color: "text-amber-700 dark:text-amber-400",
      border: "border-amber-300/80 dark:border-amber-500/20",
      glow: "shadow-amber-500/10",
    },
  };
  const statusConfig: StatusConfig = STATUS_MAP[scanState] ?? { label: "", sub: "", color: "", border: "", glow: "" };

  return (
    <motion.div
      key="status"
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.5 }}
      className="absolute inset-0 flex flex-col items-center justify-end pb-8 pointer-events-none select-none px-6"
    >
      {/* Bottom status pill */}
      <div
        className={`rounded-xl border ${statusConfig.border} bg-white/95 dark:bg-slate-950/80 backdrop-blur px-5 py-3 text-center shadow-lg ${statusConfig.glow} space-y-1 transition-colors duration-300`}
      >
        <div className={`text-xs font-mono font-bold uppercase tracking-widest ${statusConfig.color} flex items-center justify-center gap-2`}>
          {scanState === "scanning" && (
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-blue-500 dark:bg-blue-400 animate-pulse" />
          )}
          {(isBlock || scanState === "result_review") && (
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-current" />
          )}
          {isAllow && (
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-600 dark:bg-emerald-400" />
          )}
          {statusConfig.label}
        </div>
        {fileName && (
          <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate max-w-xs mx-auto">
            {fileName}
          </div>
        )}
        {statusConfig.sub && (
          <div className="text-[11px] text-slate-600 dark:text-slate-400 max-w-sm leading-relaxed mt-0.5 mx-auto">
            {statusConfig.sub}
          </div>
        )}
      </div>
    </motion.div>
  );
}

// ──────────────────────────────────────────────
// Main DropZone export
// ──────────────────────────────────────────────
export default function DropZone({
  scanState,
  fileName,
  onFileDrop,
  onAnalyzeText,
  lastResult,
}: DropZoneProps) {
  const [isDragging, setIsDragging] = useState(false);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback(() => {
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const file = e.dataTransfer.files?.[0];
      if (file) onFileDrop(file);
    },
    [onFileDrop]
  );

  const handleClick = useCallback(() => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".pdf,.txt";
    input.onchange = (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (file) onFileDrop(file);
    };
    input.click();
  }, [onFileDrop]);

  const isActive = scanState !== "idle";

  return (
    <div
      className={`relative w-full overflow-hidden rounded-2xl border transition-all duration-500 cursor-pointer group ${
        isDragging
          ? "border-emerald-500/60 shadow-lg shadow-emerald-500/10 bg-emerald-50/40 dark:bg-slate-900/60"
          : isActive
          ? scanState === "result_block"
            ? "border-red-300 dark:border-red-800/40 shadow-lg shadow-red-500/10 dark:shadow-red-900/20 bg-red-50/20 dark:bg-slate-950"
            : scanState === "result_allow"
            ? "border-emerald-300 dark:border-emerald-800/40 shadow-lg shadow-emerald-500/10 dark:shadow-emerald-900/20 bg-emerald-50/20 dark:bg-slate-950"
            : "border-blue-300 dark:border-blue-800/40 shadow-lg shadow-blue-500/10 dark:shadow-blue-900/20 bg-blue-50/20 dark:bg-slate-950"
          : "border-slate-200/90 dark:border-slate-800/60 bg-white/80 dark:bg-slate-950/80 hover:border-slate-300 dark:hover:border-slate-700/70 shadow-sm dark:shadow-none"
      }`}
      style={{ height: "360px" }}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      onClick={!isActive ? handleClick : undefined}
    >
      {/* 3D Canvas — always mounted but only visible when active */}
      <AnimatePresence>
        {isActive && (
          <motion.div
            key="canvas"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.6 }}
            className="absolute inset-0 z-10"
          >
            <Scanner3D state={scanState} />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Adaptive Vignette overlay for depth */}
      {isActive && (
        <div className="absolute inset-0 z-20 pointer-events-none [background:radial-gradient(ellipse_50%_60%_at_50%_50%,transparent_30%,rgba(248,250,252,0.65)_100%)] dark:[background:radial-gradient(ellipse_50%_60%_at_50%_50%,transparent_30%,rgba(2,6,23,0.7)_100%)]" />
      )}

      {/* Content overlays */}
      <div className="absolute inset-0 z-30">
        <AnimatePresence mode="wait">
          {scanState === "idle" ? (
            <IdleOverlay key="idle" isDragging={isDragging} />
          ) : (
            <StatusOverlay
              key="status"
              scanState={scanState}
              fileName={fileName}
              lastResult={lastResult}
            />
          )}
        </AnimatePresence>
      </div>

      {/* Grid texture overlay for idle state */}
      {scanState === "idle" && (
        <div className="absolute inset-0 opacity-[0.05] dark:opacity-[0.04] [background-image:linear-gradient(#94a3b8_1px,transparent_1px),linear-gradient(90deg,#94a3b8_1px,transparent_1px)] [background-size:40px_40px] pointer-events-none" />
      )}
    </div>
  );
}
