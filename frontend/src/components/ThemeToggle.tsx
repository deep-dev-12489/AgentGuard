"use client";

import { useEffect, useState, useRef } from "react";
import { useTheme } from "next-themes";
import { motion, AnimatePresence } from "framer-motion";
import { Sun, Moon, Monitor, ChevronDown, Check } from "lucide-react";

type ThemeOption = {
  key: "light" | "dark" | "system";
  label: string;
  badge: string;
  icon: typeof Sun;
};

const THEME_OPTIONS: ThemeOption[] = [
  { key: "light", label: "Light", badge: "DAY", icon: Sun },
  { key: "dark", label: "Dark", badge: "NIGHT", icon: Moon },
  { key: "system", label: "System", badge: "AUTO", icon: Monitor },
];

export default function ThemeToggle() {
  const { theme, setTheme, resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const [isOpen, setIsOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  // Prevent hydration mismatch
  useEffect(() => {
    setMounted(true);
  }, []);

  // Close dropdown on outside click or escape key
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setIsOpen(false);
      }
    }

    if (isOpen) {
      document.addEventListener("mousedown", handleClickOutside);
      document.addEventListener("keydown", handleKeyDown);
    }
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [isOpen]);

  if (!mounted) {
    // Return placeholder matching button footprint to prevent layout shift & hydration mismatch
    return (
      <div className="h-9 w-9 rounded-xl border border-slate-200/80 dark:border-slate-800/80 bg-white/50 dark:bg-slate-900/50 backdrop-blur-md animate-pulse" />
    );
  }

  // Determine which icon to display on the trigger
  const currentTheme = theme || "system";
  const activeIcon =
    currentTheme === "light"
      ? Sun
      : currentTheme === "dark"
      ? Moon
      : Monitor;

  const ActiveIconComponent = activeIcon;

  return (
    <div className="relative inline-block text-left" ref={containerRef}>
      {/* Trigger Button */}
      <motion.button
        type="button"
        whileTap={{ scale: 0.95 }}
        whileHover={{ scale: 1.02 }}
        onClick={() => setIsOpen((prev) => !prev)}
        aria-expanded={isOpen}
        aria-haspopup="true"
        aria-label="Toggle visual theme"
        className={`group relative flex items-center gap-2 h-9 px-3 rounded-xl border text-xs font-mono transition-all duration-200 backdrop-blur-md shadow-sm ${
          isOpen
            ? "border-emerald-500/60 bg-white dark:bg-slate-900 text-emerald-600 dark:text-emerald-400 shadow-emerald-500/10 ring-2 ring-emerald-500/20"
            : "border-slate-200 dark:border-slate-800/80 bg-white/80 dark:bg-slate-900/80 text-slate-700 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-700 hover:text-slate-900 dark:hover:text-white hover:shadow-slate-500/5 dark:hover:shadow-emerald-500/5"
        }`}
      >
        {/* Animated Icon Swap */}
        <div className="relative h-4 w-4 flex items-center justify-center">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={currentTheme}
              initial={{ rotate: -90, scale: 0.2, opacity: 0 }}
              animate={{ rotate: 0, scale: 1, opacity: 1 }}
              exit={{ rotate: 90, scale: 0.2, opacity: 0 }}
              transition={{ duration: 0.2, ease: "easeOut" }}
              className="absolute inset-0 flex items-center justify-center"
            >
              {currentTheme === "light" && (
                <Sun className="h-4 w-4 text-amber-500 filter drop-shadow-[0_0_6px_rgba(245,158,11,0.4)]" />
              )}
              {currentTheme === "dark" && (
                <Moon className="h-4 w-4 text-sky-400 filter drop-shadow-[0_0_6px_rgba(56,189,248,0.4)]" />
              )}
              {currentTheme === "system" && (
                <Monitor className="h-4 w-4 text-emerald-500 dark:text-emerald-400 filter drop-shadow-[0_0_6px_rgba(16,185,129,0.4)]" />
              )}
            </motion.div>
          </AnimatePresence>
        </div>

        {/* Current Theme Label */}
        <span className="capitalize font-semibold hidden sm:inline-block tracking-wide">
          {currentTheme}
        </span>

        {/* Dropdown Chevron */}
        <motion.div
          animate={{ rotate: isOpen ? 180 : 0 }}
          transition={{ duration: 0.2 }}
        >
          <ChevronDown className="h-3 w-3 opacity-60 group-hover:opacity-100 transition-opacity" />
        </motion.div>
      </motion.button>

      {/* Sleek Command Center Dropdown Menu */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 6, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 4, scale: 0.96 }}
            transition={{ duration: 0.18, ease: "easeOut" }}
            className="absolute right-0 mt-2 w-48 origin-top-right rounded-2xl border border-slate-200/90 dark:border-slate-800/90 bg-white/95 dark:bg-slate-950/95 backdrop-blur-2xl shadow-xl shadow-slate-900/10 dark:shadow-2xl dark:shadow-black/70 p-1.5 z-50 focus:outline-none"
            role="menu"
            aria-orientation="vertical"
          >
            {/* Header info bar */}
            <div className="px-2.5 py-1.5 mb-1 border-b border-slate-100 dark:border-slate-800/80 flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400 dark:text-slate-500 font-semibold">
                Control Plane Theme
              </span>
              <span className="flex h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
            </div>

            {/* Menu Items */}
            <div className="space-y-0.5">
              {THEME_OPTIONS.map((opt) => {
                const Icon = opt.icon;
                const isSelected = currentTheme === opt.key;

                return (
                  <button
                    key={opt.key}
                    type="button"
                    onClick={() => {
                      setTheme(opt.key);
                      setIsOpen(false);
                    }}
                    role="menuitem"
                    className={`relative w-full flex items-center justify-between px-2.5 py-2 rounded-xl text-xs font-mono transition-colors duration-150 text-left ${
                      isSelected
                        ? "text-emerald-700 dark:text-emerald-400 font-semibold"
                        : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100/70 dark:hover:bg-slate-900/60"
                    }`}
                  >
                    {/* Active highlight pill */}
                    {isSelected && (
                      <motion.div
                        layoutId="theme-active-indicator"
                        className="absolute inset-0 rounded-xl bg-emerald-500/10 dark:bg-emerald-500/15 border border-emerald-500/30 dark:border-emerald-500/30"
                        transition={{ type: "spring", stiffness: 380, damping: 30 }}
                      />
                    )}

                    <div className="relative z-10 flex items-center gap-2.5">
                      <div
                        className={`h-6 w-6 rounded-lg flex items-center justify-center border transition-colors ${
                          isSelected
                            ? "border-emerald-500/40 bg-emerald-500/20 text-emerald-600 dark:text-emerald-300 shadow-sm shadow-emerald-500/10"
                            : "border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 text-slate-500 dark:text-slate-400"
                        }`}
                      >
                        <Icon className="h-3.5 w-3.5" />
                      </div>
                      <span className="tracking-tight">{opt.label}</span>
                    </div>

                    <div className="relative z-10 flex items-center gap-2">
                      <span
                        className={`text-[9px] font-mono px-1.5 py-0.5 rounded uppercase tracking-wider ${
                          isSelected
                            ? "bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30"
                            : "bg-slate-100 dark:bg-slate-800/80 text-slate-400 dark:text-slate-500"
                        }`}
                      >
                        {opt.badge}
                      </span>
                      {isSelected && (
                        <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
                      )}
                    </div>
                  </button>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
