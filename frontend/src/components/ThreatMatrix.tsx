"use client";

import { motion, AnimatePresence } from "framer-motion";
import type { AuditLogEntry, Verdict } from "@/types";

interface ThreatMatrixProps {
  logs: AuditLogEntry[];
  onRowClick: (entry: AuditLogEntry) => void;
  selectedId: string | null;
}

// ──────────────────────────────────────────────
// Verdict badge component
// ──────────────────────────────────────────────
function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const config = {
    ALLOW: {
      label: "ALLOW",
      classes:
        "bg-emerald-50 border-emerald-400/60 text-emerald-700 shadow-emerald-500/10 dark:bg-emerald-500/10 dark:border-emerald-500/30 dark:text-emerald-400 dark:shadow-emerald-500/20",
      dot: "bg-emerald-600 dark:bg-emerald-400",
    },
    BLOCK: {
      label: "BLOCK",
      classes:
        "bg-red-50 border-red-400/60 text-red-700 shadow-red-500/10 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400 dark:shadow-red-500/20",
      dot: "bg-red-600 dark:bg-red-400",
    },
    REVIEW: {
      label: "REVIEW",
      classes:
        "bg-amber-50 border-amber-400/60 text-amber-800 shadow-amber-500/10 dark:bg-amber-500/10 dark:border-amber-500/30 dark:text-amber-400 dark:shadow-amber-500/20",
      dot: "bg-amber-600 dark:bg-amber-400",
    },
  }[verdict];

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[10px] font-mono font-bold uppercase tracking-widest shadow-sm transition-colors ${config.classes}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${config.dot} animate-pulse`} />
      {config.label}
    </span>
  );
}

// ──────────────────────────────────────────────
// Single row component
// ──────────────────────────────────────────────
function LogRow({
  entry,
  index,
  isSelected,
  onClick,
}: {
  entry: AuditLogEntry;
  index: number;
  isSelected: boolean;
  onClick: () => void;
}) {
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, x: -20 }}
      transition={{ duration: 0.35, delay: index * 0.04, ease: "easeOut" }}
      whileHover={{ scale: 1.005 }}
      onClick={onClick}
      className={`group relative flex items-center gap-4 px-5 py-3.5 cursor-pointer rounded-lg transition-colors duration-150 ${
        isSelected
          ? entry.verdict === "BLOCK"
            ? "bg-red-50/80 border border-red-300 dark:bg-red-950/30 dark:border-red-800/40"
            : entry.verdict === "ALLOW"
            ? "bg-emerald-50/80 border border-emerald-300 dark:bg-emerald-950/30 dark:border-emerald-800/40"
            : "bg-amber-50/80 border border-amber-300 dark:bg-amber-950/30 dark:border-amber-800/40"
          : "border border-transparent hover:bg-slate-100/90 dark:hover:bg-slate-900/60 hover:border-slate-200 dark:hover:border-slate-800/80"
      }`}
    >
      {/* Left accent bar */}
      <motion.div
        className={`absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-6 rounded-full transition-colors duration-150 ${
          isSelected
            ? entry.verdict === "BLOCK"
              ? "bg-red-500"
              : entry.verdict === "ALLOW"
              ? "bg-emerald-500"
              : "bg-amber-500"
            : "bg-transparent group-hover:bg-slate-300 dark:group-hover:bg-slate-600"
        }`}
      />

      {/* Timestamp */}
      <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 shrink-0 w-20">
        {entry.timestamp}
      </span>

      {/* File name */}
      <span className="flex-1 text-sm text-slate-800 dark:text-slate-200 font-medium truncate leading-tight">
        {entry.fileName}
        {entry.riskLevel && entry.riskLevel !== "LOW" && (
          <span
            className={`ml-2 text-[9px] font-mono font-bold uppercase px-1.5 py-0.5 rounded ${
              entry.riskLevel === "CRITICAL"
                ? "text-red-700 bg-red-100 border border-red-300 dark:text-red-300 dark:bg-red-950/50 dark:border-red-800/50"
                : entry.riskLevel === "HIGH"
                ? "text-orange-700 bg-orange-100 border border-orange-300 dark:text-orange-300 dark:bg-orange-950/50 dark:border-orange-800/50"
                : "text-amber-700 bg-amber-100 border border-amber-300 dark:text-amber-300 dark:bg-amber-950/50 dark:border-amber-800/50"
            }`}
          >
            {entry.riskLevel}
          </span>
        )}
      </span>

      {/* Verdict badge */}
      <div className="shrink-0">
        <VerdictBadge verdict={entry.verdict} />
      </div>

      {/* Inspect arrow */}
      <span
        className={`text-xs transition-all duration-200 shrink-0 ${
          isSelected
            ? "opacity-100 text-slate-700 dark:text-slate-400"
            : "opacity-0 group-hover:opacity-100 text-slate-400 dark:text-slate-600"
        }`}
      >
        →
      </span>
    </motion.div>
  );
}

// ──────────────────────────────────────────────
// Empty state
// ──────────────────────────────────────────────
function EmptyState() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="flex flex-col items-center justify-center py-16 gap-3"
    >
      <div className="h-12 w-12 rounded-full bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-center shadow-inner">
        <span className="text-slate-400 dark:text-slate-600 text-xl font-mono">⬡</span>
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-500 font-mono">
        No scans yet — deploy a document above
      </p>
    </motion.div>
  );
}

// ──────────────────────────────────────────────
// Main ThreatMatrix export
// ──────────────────────────────────────────────
export default function ThreatMatrix({ logs, onRowClick, selectedId }: ThreatMatrixProps) {
  const blockCount = logs.filter((l) => l.verdict === "BLOCK").length;
  const allowCount = logs.filter((l) => l.verdict === "ALLOW").length;
  const reviewCount = logs.filter((l) => l.verdict === "REVIEW").length;

  return (
    <div className="space-y-3">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h2 className="font-display text-sm font-semibold text-slate-800 dark:text-slate-200 tracking-tight">
            Threat Matrix
          </h2>
          {logs.length > 0 && (
            <span className="text-[10px] font-mono text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 px-2 py-0.5 rounded-md">
              {logs.length} scan{logs.length !== 1 ? "s" : ""}
            </span>
          )}
        </div>

        {/* Summary chips */}
        {logs.length > 0 && (
          <div className="flex items-center gap-2">
            {allowCount > 0 && (
              <span className="text-[10px] font-mono font-bold text-emerald-700 dark:text-emerald-400 bg-emerald-500/10 dark:bg-emerald-500/8 border border-emerald-300 dark:border-emerald-800/40 px-2 py-0.5 rounded-md">
                {allowCount} ALLOW
              </span>
            )}
            {blockCount > 0 && (
              <span className="text-[10px] font-mono font-bold text-red-700 dark:text-red-400 bg-red-500/10 dark:bg-red-500/8 border border-red-300 dark:border-red-800/40 px-2 py-0.5 rounded-md">
                {blockCount} BLOCK
              </span>
            )}
            {reviewCount > 0 && (
              <span className="text-[10px] font-mono font-bold text-amber-700 dark:text-amber-400 bg-amber-500/10 dark:bg-amber-500/8 border border-amber-300 dark:border-amber-800/40 px-2 py-0.5 rounded-md">
                {reviewCount} REVIEW
              </span>
            )}
          </div>
        )}
      </div>

      {/* Column headers */}
      {logs.length > 0 && (
        <div className="flex items-center gap-4 px-5 pb-1">
          <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-widest w-20">
            Time
          </span>
          <span className="flex-1 text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-widest">
            Document
          </span>
          <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-widest shrink-0">
            Verdict
          </span>
          <span className="w-4" />
        </div>
      )}

      {/* Divider */}
      {logs.length > 0 && <div className="h-px bg-slate-200 dark:bg-slate-800/60" />}

      {/* Rows */}
      <div className="space-y-1">
        <AnimatePresence>
          {logs.length === 0 ? (
            <EmptyState />
          ) : (
            [...logs].reverse().map((entry, i) => (
              <LogRow
                key={entry.id}
                entry={entry}
                index={i}
                isSelected={selectedId === entry.id}
                onClick={() => onRowClick(entry)}
              />
            ))
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
