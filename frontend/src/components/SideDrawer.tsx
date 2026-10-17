"use client";

import { motion, AnimatePresence } from "framer-motion";
import { X, Shield, ShieldAlert, ShieldCheck, ChevronRight } from "lucide-react";
import type { AuditLogEntry, LineageNode } from "@/types";

interface SideDrawerProps {
  entry: AuditLogEntry | null;
  onClose: () => void;
}

// ──────────────────────────────────────────────
// Syntax-highlighted JSON viewer
// ──────────────────────────────────────────────
function JsonViewer({ data }: { data: unknown }) {
  const json = JSON.stringify(data, null, 2);

  // Simple tokenizer for colorization
  const tokens = json.split(/("(?:[^"\\]|\\.)*"(?:\s*:)?|\btrue\b|\bfalse\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}[\],])/g);

  return (
    <pre className="text-[11px] font-mono leading-relaxed overflow-x-auto whitespace-pre-wrap break-words">
      {tokens.map((token, i) => {
        if (token === "") return null;

        // String key (ends with :)
        if (/^"[^"]*"\s*:$/.test(token)) {
          return (
            <span key={i} className="text-blue-700 dark:text-blue-300 font-medium">
              {token}
            </span>
          );
        }
        // String value
        if (/^"[^"]*"$/.test(token)) {
          return (
            <span key={i} className="text-emerald-700 dark:text-emerald-300">
              {token}
            </span>
          );
        }
        // Boolean
        if (token === "true") return <span key={i} className="text-cyan-700 dark:text-cyan-400 font-semibold">{token}</span>;
        if (token === "false") return <span key={i} className="text-red-700 dark:text-red-400 font-semibold">{token}</span>;
        if (token === "null") return <span key={i} className="text-slate-400 dark:text-slate-500 italic">{token}</span>;
        // Number
        if (/^-?\d/.test(token)) return <span key={i} className="text-amber-700 dark:text-amber-300">{token}</span>;
        // Braces
        if (["{", "}", "[", "]"].includes(token))
          return <span key={i} className="text-slate-600 dark:text-slate-500">{token}</span>;
        // Commas
        if (token === ",") return <span key={i} className="text-slate-400 dark:text-slate-600">{token}</span>;

        return <span key={i} className="text-slate-700 dark:text-slate-400">{token}</span>;
      })}
    </pre>
  );
}

// ──────────────────────────────────────────────
// Action lineage chain
// ──────────────────────────────────────────────
function LineageChain({ nodes }: { nodes: LineageNode[] }) {
  if (!nodes || nodes.length === 0) return null;

  return (
    <div className="space-y-2">
      {nodes.map((node, i) => (
        <div key={node.id} className="flex items-start gap-2">
          {/* Connector line */}
          <div className="flex flex-col items-center shrink-0 pt-1">
            <div
              className={`h-2 w-2 rounded-full border ${
                node.is_tainted
                  ? "bg-red-500/20 border-red-500/60"
                  : "bg-emerald-500/20 border-emerald-500/60"
              }`}
            />
            {i < nodes.length - 1 && (
              <div className="w-px flex-1 bg-slate-200 dark:bg-slate-800 mt-1" style={{ minHeight: "12px" }} />
            )}
          </div>

          {/* Node content */}
          <div className="pb-3 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {node.type}
              </span>
              {node.is_tainted && (
                <span className="text-[9px] font-mono text-red-700 dark:text-red-400 bg-red-100 dark:bg-red-950/40 border border-red-300 dark:border-red-800/40 px-1 py-0.5 rounded font-bold">
                  TAINTED
                </span>
              )}
            </div>
            <p className="text-xs text-slate-800 dark:text-slate-200 font-medium mt-0.5">{node.label}</p>
            {node.details && (
              <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 leading-relaxed">{node.details}</p>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

// ──────────────────────────────────────────────
// Section wrapper
// ──────────────────────────────────────────────
function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2.5">
      <div className="flex items-center gap-2">
        <div className="h-px flex-1 bg-slate-200 dark:bg-slate-800/80" />
        <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase tracking-widest shrink-0 font-semibold">
          {title}
        </span>
        <div className="h-px flex-1 bg-slate-200 dark:bg-slate-800/80" />
      </div>
      <div>{children}</div>
    </div>
  );
}

// ──────────────────────────────────────────────
// Main SideDrawer export
// ──────────────────────────────────────────────
export default function SideDrawer({ entry, onClose }: SideDrawerProps) {
  const decision = entry?.payload?.security_decision;
  const verdict = entry?.verdict;
  const isBlock = verdict === "BLOCK";
  const isAllow = verdict === "ALLOW";

  return (
    <AnimatePresence>
      {entry && (
        <>
          {/* Backdrop */}
          <motion.div
            key="backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.25 }}
            onClick={onClose}
            className="fixed inset-0 z-40 bg-slate-900/30 dark:bg-black/50 backdrop-blur-sm"
          />

          {/* Drawer */}
          <motion.aside
            key="drawer"
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ type: "spring", stiffness: 320, damping: 32, mass: 0.9 }}
            className={`fixed right-0 top-0 bottom-0 z-50 w-full max-w-lg flex flex-col overflow-hidden bg-white/95 dark:bg-slate-950/95 backdrop-blur-2xl border-l transition-colors duration-300 shadow-2xl ${
              isBlock
                ? "border-red-300/80 dark:border-red-500/20"
                : isAllow
                ? "border-emerald-300/80 dark:border-emerald-500/20"
                : "border-amber-300/80 dark:border-amber-500/20"
            }`}
          >
            {/* Accent glow */}
            <div
              className={`absolute top-0 right-0 w-64 h-64 rounded-full pointer-events-none blur-3xl opacity-15 dark:opacity-10 ${
                isBlock
                  ? "bg-red-400 dark:bg-red-500"
                  : isAllow
                  ? "bg-emerald-400 dark:bg-emerald-500"
                  : "bg-amber-400 dark:bg-amber-500"
              }`}
            />

            {/* Header */}
            <div className="relative z-10 flex items-start justify-between px-6 py-5 border-b border-slate-200/90 dark:border-slate-800/60">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  {isBlock ? (
                    <ShieldAlert className="h-4 w-4 text-red-600 dark:text-red-400" />
                  ) : isAllow ? (
                    <ShieldCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                  ) : (
                    <Shield className="h-4 w-4 text-amber-600 dark:text-amber-400" />
                  )}
                  <span
                    className={`text-xs font-mono font-bold uppercase tracking-widest ${
                      isBlock
                        ? "text-red-700 dark:text-red-400"
                        : isAllow
                        ? "text-emerald-700 dark:text-emerald-400"
                        : "text-amber-700 dark:text-amber-400"
                    }`}
                  >
                    {verdict} — Inspection Report
                  </span>
                </div>
                <h3 className="font-display text-base font-semibold text-slate-900 dark:text-white leading-tight truncate max-w-xs">
                  {entry.fileName}
                </h3>
                <p className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                  Scanned at {entry.timestamp}
                </p>
              </div>

              <button
                onClick={onClose}
                className="h-8 w-8 rounded-lg flex items-center justify-center text-slate-400 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Scrollable body */}
            <div className="relative z-10 flex-1 overflow-y-auto px-6 py-5 space-y-6 scrollbar-thin scrollbar-track-transparent scrollbar-thumb-slate-300 dark:scrollbar-thumb-slate-800">

              {/* Summary card */}
              <div
                className={`rounded-lg border p-4 space-y-2 transition-colors ${
                  isBlock
                    ? "bg-red-50/80 border-red-200 dark:bg-red-950/20 dark:border-red-800/40"
                    : isAllow
                    ? "bg-emerald-50/80 border-emerald-200 dark:bg-emerald-950/20 dark:border-emerald-800/40"
                    : "bg-amber-50/80 border-amber-200 dark:bg-amber-950/20 dark:border-amber-800/40"
                }`}
              >
                <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed font-sans">
                  {decision?.reason || entry.payload.summary}
                </p>
                <div className="flex flex-wrap gap-2 pt-1">
                  {decision?.risk_level && (
                    <span
                      className={`text-[9px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${
                        decision.risk_level === "CRITICAL"
                          ? "text-red-700 bg-red-100 border-red-300 dark:text-red-300 dark:bg-red-950/50 dark:border-red-800/50"
                          : decision.risk_level === "HIGH"
                          ? "text-orange-700 bg-orange-100 border-orange-300 dark:text-orange-300 dark:bg-orange-950/50 dark:border-orange-800/50"
                          : decision.risk_level === "MEDIUM"
                          ? "text-amber-700 bg-amber-100 border-amber-300 dark:text-amber-300 dark:bg-amber-950/50 dark:border-amber-800/50"
                          : "text-slate-700 bg-slate-100 border-slate-300 dark:text-slate-400 dark:bg-slate-900/50 dark:border-slate-800/50"
                      }`}
                    >
                      Risk: {decision.risk_level}
                    </span>
                  )}
                  {entry.payload.mode && (
                    <span className="text-[9px] font-mono text-slate-600 dark:text-slate-400 px-2 py-0.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-100/80 dark:bg-slate-900/50 uppercase tracking-wider">
                      {entry.payload.mode}
                    </span>
                  )}
                  {entry.payload.tool_call_attempted && (
                    <span className="text-[9px] font-mono text-blue-700 dark:text-blue-300 px-2 py-0.5 rounded border border-blue-200 dark:border-blue-800/40 bg-blue-50 dark:bg-blue-950/30 uppercase tracking-wider">
                      Tool: {entry.payload.tool_call_attempted}
                    </span>
                  )}
                </div>
              </div>

              {/* Checks fired */}
              {decision?.checks_fired && decision.checks_fired.length > 0 && (
                <Section title="Policy Checks Fired">
                  <div className="flex flex-wrap gap-1.5">
                    {decision.checks_fired.map((check) => (
                      <span
                        key={check}
                        className="text-[10px] font-mono text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800/40 px-2 py-1 rounded font-medium"
                      >
                        {check}
                      </span>
                    ))}
                  </div>
                </Section>
              )}

              {/* Extracted claims */}
              {entry.payload.extracted_claims?.length > 0 && (
                <Section title="Extracted Claims">
                  <ul className="space-y-1.5">
                    {entry.payload.extracted_claims.map((claim, i) => (
                      <motion.li
                        key={i}
                        initial={{ opacity: 0, x: 6 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.05 }}
                        className="flex items-start gap-2 text-xs text-slate-700 dark:text-slate-300"
                      >
                        <ChevronRight className="h-3 w-3 text-slate-400 dark:text-slate-600 mt-0.5 shrink-0" />
                        {claim}
                      </motion.li>
                    ))}
                  </ul>
                </Section>
              )}

              {/* Action lineage */}
              {entry.payload.action_lineage?.length > 0 && (
                <Section title="Action Lineage">
                  <LineageChain nodes={entry.payload.action_lineage} />
                </Section>
              )}

              {/* Raw JSON payload */}
              <Section title="Raw Security Payload">
                <div className="rounded-lg bg-slate-100/80 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800/60 p-4 overflow-hidden shadow-inner">
                  <JsonViewer data={entry.payload} />
                </div>
              </Section>
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}
