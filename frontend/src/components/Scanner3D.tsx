"use client";

import React, { useRef, useMemo, useState, useEffect } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Float } from "@react-three/drei";
import * as THREE from "three";
import { useTheme } from "next-themes";
import { motion, AnimatePresence } from "framer-motion";
import type { ScanState } from "@/types";

// ============================================================================
// COLOR CONSTANTS & THEME PALETTES
// ============================================================================

interface StateColorPalette {
  laser: string;
  coreAttenuation: string;
  innerEmissive: string;
  uiBadgeBg: string;
  uiBadgeBorder: string;
  uiBadgeText: string;
  uiDot: string;
}

const PALETTE_LIGHT: Record<ScanState, StateColorPalette> = {
  idle: {
    laser: "#0284c7", // Cobalt Blue
    coreAttenuation: "#f0f9ff",
    innerEmissive: "#0284c7",
    uiBadgeBg: "bg-sky-500/10",
    uiBadgeBorder: "border-sky-500/30",
    uiBadgeText: "text-sky-800",
    uiDot: "bg-sky-600",
  },
  scanning: {
    laser: "#2563eb", // Deep Royal Cobalt
    coreAttenuation: "#eff6ff",
    innerEmissive: "#2563eb",
    uiBadgeBg: "bg-blue-500/10",
    uiBadgeBorder: "border-blue-500/30",
    uiBadgeText: "text-blue-800",
    uiDot: "bg-blue-600",
  },
  result_allow: {
    laser: "#059669", // High-Contrast Deep Emerald
    coreAttenuation: "#ecfdf5",
    innerEmissive: "#059669",
    uiBadgeBg: "bg-emerald-500/10",
    uiBadgeBorder: "border-emerald-500/30",
    uiBadgeText: "text-emerald-800",
    uiDot: "bg-emerald-600",
  },
  result_block: {
    laser: "#dc2626", // High-Contrast Crimson Red
    coreAttenuation: "#fef2f2",
    innerEmissive: "#dc2626",
    uiBadgeBg: "bg-red-500/10",
    uiBadgeBorder: "border-red-500/30",
    uiBadgeText: "text-red-800",
    uiDot: "bg-red-600",
  },
  result_review: {
    laser: "#d97706", // High-Contrast Warm Amber
    coreAttenuation: "#fffbeb",
    innerEmissive: "#d97706",
    uiBadgeBg: "bg-amber-500/10",
    uiBadgeBorder: "border-amber-500/30",
    uiBadgeText: "text-amber-800",
    uiDot: "bg-amber-600",
  },
};

const PALETTE_DARK: Record<ScanState, StateColorPalette> = {
  idle: {
    laser: "#38bdf8", // Electric Sky Cyan
    coreAttenuation: "#082f49",
    innerEmissive: "#38bdf8",
    uiBadgeBg: "bg-sky-500/15",
    uiBadgeBorder: "border-sky-500/40",
    uiBadgeText: "text-sky-300",
    uiDot: "bg-sky-400",
  },
  scanning: {
    laser: "#00f0ff", // Vibrant Electric Cyan
    coreAttenuation: "#083344",
    innerEmissive: "#00f0ff",
    uiBadgeBg: "bg-cyan-500/15",
    uiBadgeBorder: "border-cyan-500/40",
    uiBadgeText: "text-cyan-300",
    uiDot: "bg-cyan-400",
  },
  result_allow: {
    laser: "#10b981", // Glowing Neon Emerald
    coreAttenuation: "#064e3b",
    innerEmissive: "#10b981",
    uiBadgeBg: "bg-emerald-500/15",
    uiBadgeBorder: "border-emerald-500/40",
    uiBadgeText: "text-emerald-300",
    uiDot: "bg-emerald-400",
  },
  result_block: {
    laser: "#ff1744", // Vibrant Glowing Neon Red
    coreAttenuation: "#7f1d1d",
    innerEmissive: "#ff1744",
    uiBadgeBg: "bg-rose-500/15",
    uiBadgeBorder: "border-rose-500/40",
    uiBadgeText: "text-rose-300",
    uiDot: "bg-rose-400",
  },
  result_review: {
    laser: "#f59e0b", // Glowing Neon Amber
    coreAttenuation: "#78350f",
    innerEmissive: "#f59e0b",
    uiBadgeBg: "bg-amber-500/15",
    uiBadgeBorder: "border-amber-500/40",
    uiBadgeText: "text-amber-300",
    uiDot: "bg-amber-400",
  },
};

// ────────────────────────────────────────────────────────────────────────────
// SUB-COMPONENT: Ambient Sparse Particle Field
// Subtle, calm background particles drifting slowly. Zero chaotic fast motion.
// ────────────────────────────────────────────────────────────────────────────
function AmbientParticles({
  isDark,
  stateColor,
}: {
  isDark: boolean;
  stateColor: string;
}) {
  const count = 90;
  const pointsRef = useRef<THREE.Points>(null!);

  const { positions, speeds } = useMemo(() => {
    const pos = new Float32Array(count * 3);
    const spd = new Float32Array(count);
    for (let i = 0; i < count; i++) {
      pos[i * 3] = (Math.random() - 0.5) * 8.0;
      pos[i * 3 + 1] = (Math.random() - 0.5) * 6.5;
      pos[i * 3 + 2] = (Math.random() - 0.5) * 5.0;
      spd[i] = 0.25 + Math.random() * 0.5;
    }
    return { positions: pos, speeds: spd };
  }, [count]);

  useFrame(({ clock }) => {
    if (!pointsRef.current?.geometry?.attributes?.position) return;
    const posArray = pointsRef.current.geometry.attributes.position
      .array as Float32Array;

    for (let i = 0; i < count; i++) {
      // Very slow vertical drift
      posArray[i * 3 + 1] += speeds[i] * 0.0018;
      if (posArray[i * 3 + 1] > 3.25) {
        posArray[i * 3 + 1] = -3.25;
      }
    }
    pointsRef.current.geometry.attributes.position.needsUpdate = true;
    pointsRef.current.rotation.y = clock.getElapsedTime() * 0.015;
  });

  const particleColor = isDark ? "#94a3b8" : "#64748b";

  return (
    <points ref={pointsRef}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial
        size={isDark ? 0.035 : 0.042}
        color={particleColor}
        transparent
        opacity={isDark ? 0.38 : 0.28}
        sizeAttenuation
        depthWrite={false}
      />
    </points>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// SUB-COMPONENT: Sleek Solid Geometric Core (Glassmorphism & Obsidian)
// Pure solid geometry, MeshPhysicalMaterial with transmission, zero wireframes.
// ────────────────────────────────────────────────────────────────────────────
function QuantumSolidCore({
  state,
  isDark,
  palette,
}: {
  state: ScanState;
  isDark: boolean;
  palette: StateColorPalette;
}) {
  const outerGroupRef = useRef<THREE.Group>(null!);
  const outerMeshRef = useRef<THREE.Mesh>(null!);
  const innerMeshRef = useRef<THREE.Mesh>(null!);
  const physicalMatRef = useRef<THREE.MeshPhysicalMaterial>(null!);
  const innerMatRef = useRef<THREE.MeshStandardMaterial>(null!);

  const isScanning = state === "scanning";
  const isBlock = state === "result_block";
  const isAllow = state === "result_allow";

  useFrame((_, delta) => {
    if (!outerGroupRef.current) return;

    // Slow, majestic continuous rotation
    outerGroupRef.current.rotation.y += delta * 0.38;
    outerGroupRef.current.rotation.x += delta * 0.12;

    if (innerMeshRef.current) {
      // Counter-rotation for the cryptographic inner node
      innerMeshRef.current.rotation.y -= delta * 0.55;
      innerMeshRef.current.rotation.z += delta * 0.25;
    }

    // State-reactive subtle breathing pulse
    const t = performance.now() * 0.001;
    let pulseScale = 1.0;
    if (isScanning) {
      pulseScale = 1.0 + Math.sin(t * 3.5) * 0.035;
    } else if (isBlock) {
      pulseScale = 1.0 + Math.sin(t * 7.0) * 0.045;
    } else if (isAllow) {
      pulseScale = 1.0 + Math.sin(t * 1.5) * 0.02;
    } else {
      pulseScale = 1.0 + Math.sin(t * 0.8) * 0.015;
    }

    outerGroupRef.current.scale.set(pulseScale, pulseScale, pulseScale);
  });

  // Dynamic color updating for materials
  useEffect(() => {
    if (physicalMatRef.current) {
      physicalMatRef.current.attenuationColor.set(palette.coreAttenuation);
      physicalMatRef.current.color.set(isDark ? "#060a12" : "#ffffff");
      physicalMatRef.current.needsUpdate = true;
    }
    if (innerMatRef.current) {
      innerMatRef.current.emissive.set(palette.innerEmissive);
      innerMatRef.current.needsUpdate = true;
    }
  }, [palette, isDark]);

  return (
    <Float
      speed={1.8}
      rotationIntensity={0.5}
      floatIntensity={0.6}
      floatingRange={[-0.12, 0.12]}
    >
      <group ref={outerGroupRef}>
        {/* 1. Inner Solid Cryptographic Enclave (Renders first into transmission buffer) */}
        <mesh ref={innerMeshRef} renderOrder={1}>
          <octahedronGeometry args={[0.52, 0]} />
          <meshStandardMaterial
            ref={innerMatRef}
            color={isDark ? "#0f172a" : "#334155"}
            roughness={isDark ? 0.15 : 0.25}
            metalness={0.9}
            emissive={palette.innerEmissive}
            emissiveIntensity={
              isDark
                ? isBlock
                  ? 1.4
                  : isAllow
                  ? 1.1
                  : isScanning
                  ? 0.95
                  : 0.4
                : isBlock
                ? 0.7
                : isAllow
                ? 0.5
                : isScanning
                ? 0.4
                : 0.15
            }
          />
        </mesh>

        {/* 2. Outer Solid Faceted Monolith: Glassmorphism / Obsidian Shell */}
        <mesh ref={outerMeshRef} renderOrder={2}>
          <icosahedronGeometry args={[1.18, 0]} />
          <meshPhysicalMaterial
            ref={physicalMatRef}
            color={isDark ? "#060a12" : "#ffffff"}
            roughness={isDark ? 0.06 : 0.12}
            metalness={isDark ? 0.28 : 0.04}
            transmission={isDark ? 0.55 : 0.94}
            thickness={isDark ? 2.4 : 1.8}
            ior={isDark ? 1.72 : 1.54}
            reflectivity={0.95}
            clearcoat={1.0}
            clearcoatRoughness={isDark ? 0.04 : 0.08}
            attenuationColor={palette.coreAttenuation}
            attenuationDistance={isDark ? 1.4 : 2.0}
            specularIntensity={1.0}
            transparent
            depthWrite={false}
          />
        </mesh>
      </group>
    </Float>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// SUB-COMPONENT: Horizontal Scanning Laser Sweep Plane
// Distinct glowing horizontal plane moving smoothly via sine wave. Zero wireframes.
// ────────────────────────────────────────────────────────────────────────────
function LaserSweepPlane({
  state,
  isDark,
  laserColor,
}: {
  state: ScanState;
  isDark: boolean;
  laserColor: string;
}) {
  const sweepGroupRef = useRef<THREE.Group>(null!);
  const currentYRef = useRef(0);

  const isScanning = state === "scanning";
  const isBlock = state === "result_block";
  const isAllow = state === "result_allow";
  const isReview = state === "result_review";

  useFrame(({ clock }, delta) => {
    if (!sweepGroupRef.current) return;
    const t = clock.getElapsedTime();

    // Target vertical sine-wave position based on security scan state
    let targetY = 0;
    if (isScanning) {
      targetY = Math.sin(t * 2.2) * 1.55;
    } else if (isBlock) {
      // Quarantined barrier oscillation at center-top
      targetY = 0.25 + Math.sin(t * 5.0) * 0.08;
    } else if (isAllow) {
      // Calm, grounded verification beam
      targetY = Math.sin(t * 1.2) * 0.12;
    } else if (isReview) {
      targetY = Math.sin(t * 1.5) * 0.75;
    } else {
      // Idle standby gentle breathing
      targetY = Math.sin(t * 0.9) * 0.85;
    }

    // Smooth physics interpolation
    currentYRef.current = THREE.MathUtils.lerp(
      currentYRef.current,
      targetY,
      delta * 5.0
    );
    sweepGroupRef.current.position.y = currentYRef.current;
  });

  const discOpacity = isDark
    ? isBlock
      ? 0.22
      : isAllow
      ? 0.18
      : 0.14
    : isBlock
    ? 0.32
    : isAllow
    ? 0.26
    : 0.2;

  const ringOpacity = isDark ? 0.95 : 0.88;

  return (
    <group ref={sweepGroupRef}>
      {/* 1. Main Solid Laser Scanning Disc */}
      <mesh rotation={[-Math.PI / 2, 0, 0]}>
        <circleGeometry args={[2.05, 64]} />
        <meshBasicMaterial
          color={laserColor}
          transparent
          opacity={discOpacity}
          blending={isDark ? THREE.AdditiveBlending : THREE.NormalBlending}
          side={THREE.DoubleSide}
          depthWrite={false}
        />
      </mesh>

      {/* 2. Razor-Sharp Outer Laser Perimeter */}
      <mesh rotation={[-Math.PI / 2, 0, 0]}>
        <ringGeometry args={[1.99, 2.05, 64]} />
        <meshBasicMaterial
          color={laserColor}
          transparent
          opacity={ringOpacity}
          side={THREE.DoubleSide}
        />
      </mesh>

      {/* 3. Concentric Precision Reticle Ring */}
      <mesh rotation={[-Math.PI / 2, 0, 0]}>
        <ringGeometry args={[1.36, 1.385, 48]} />
        <meshBasicMaterial
          color={laserColor}
          transparent
          opacity={isDark ? 0.55 : 0.45}
          side={THREE.DoubleSide}
        />
      </mesh>

      {/* 4. Fine Optical Crosshair Guideline */}
      <mesh rotation={[-Math.PI / 2, 0, 0]}>
        <planeGeometry args={[4.1, 0.015]} />
        <meshBasicMaterial
          color={laserColor}
          transparent
          opacity={isDark ? 0.45 : 0.35}
          side={THREE.DoubleSide}
        />
      </mesh>
      <mesh rotation={[-Math.PI / 2, 0, Math.PI / 2]}>
        <planeGeometry args={[4.1, 0.015]} />
        <meshBasicMaterial
          color={laserColor}
          transparent
          opacity={isDark ? 0.45 : 0.35}
          side={THREE.DoubleSide}
        />
      </mesh>

      {/* 5. Volumetric Laser Light Sheet Flare */}
      <mesh>
        <cylinderGeometry args={[2.05, 2.05, 0.16, 64, 1, true]} />
        <meshBasicMaterial
          color={laserColor}
          transparent
          opacity={isDark ? 0.18 : 0.14}
          blending={isDark ? THREE.AdditiveBlending : THREE.NormalBlending}
          side={THREE.DoubleSide}
          depthWrite={false}
        />
      </mesh>

      {/* 6. Co-located Point Light: Tracks laser height, projecting dynamic caustics */}
      <pointLight
        color={laserColor}
        intensity={
          isDark
            ? isBlock
              ? 11.0
              : isAllow
              ? 9.5
              : isScanning
              ? 8.5
              : 5.5
            : isBlock
            ? 6.5
            : isAllow
            ? 5.5
            : isScanning
            ? 4.8
            : 3.2
        }
        distance={5.8}
        decay={2}
      />
    </group>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// SUB-COMPONENT: Adaptive Lighting Rig
// Strictly adjusts intensity and color according to current theme and scanner state.
// ────────────────────────────────────────────────────────────────────────────
function AdaptiveLighting({
  isDark,
  state,
  stateColor,
}: {
  isDark: boolean;
  state: ScanState;
  stateColor: string;
}) {
  const isBlock = state === "result_block";
  const isAllow = state === "result_allow";

  return (
    <>
      {/* 1. Global Ambient Base Light */}
      <ambientLight
        color={isDark ? "#0f172a" : "#ffffff"}
        intensity={isDark ? 0.45 : 1.05}
      />

      {/* 2. Key Directional Light for Crisp Specular Highlights */}
      <directionalLight
        position={[4.5, 6.0, 4.0]}
        color={isDark ? "#f8fafc" : "#ffffff"}
        intensity={isDark ? 1.3 : 1.85}
      />

      {/* 3. Rim/Fill Directional Light for Depth & Shadow Definition */}
      <directionalLight
        position={[-4.5, -3.5, -2.5]}
        color={isDark ? "#1e293b" : "#94a3b8"}
        intensity={isDark ? 0.5 : 0.65}
      />

      {/* 4. Core Specular Backlight */}
      <pointLight
        position={[0, 0, -2.8]}
        color={stateColor}
        intensity={
          isDark
            ? isBlock
              ? 3.2
              : isAllow
              ? 2.8
              : 2.2
            : isBlock
            ? 1.2
            : isAllow
            ? 1.0
            : 0.75
        }
        distance={6.5}
        decay={2}
      />
    </>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// SUB-COMPONENT: Complete 3D Scene Assembly
// ────────────────────────────────────────────────────────────────────────────
function Scene({
  state,
  isDark,
  palette,
}: {
  state: ScanState;
  isDark: boolean;
  palette: StateColorPalette;
}) {
  return (
    <>
      <AdaptiveLighting
        isDark={isDark}
        state={state}
        stateColor={palette.laser}
      />
      <AmbientParticles isDark={isDark} stateColor={palette.laser} />
      <QuantumSolidCore state={state} isDark={isDark} palette={palette} />
      <LaserSweepPlane
        state={state}
        isDark={isDark}
        laserColor={palette.laser}
      />
    </>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// SUB-COMPONENT: Minimalist Enterprise Telemetry Overlay (Framer Motion)
// Zero-friction, pointer-events-none HUD badge system for high-security telemetry.
// ────────────────────────────────────────────────────────────────────────────
function EnterpriseTelemetryOverlay({
  state,
  palette,
}: {
  state: ScanState;
  palette: StateColorPalette;
}) {
  const getBadgeLabel = (s: ScanState) => {
    switch (s) {
      case "result_allow":
        return "ZERO-TRUST VERIFIED // ALLOW";
      case "result_block":
        return "THREAT CONTAINED // BLOCKED";
      case "result_review":
        return "ELEVATED RISK // MANUAL REVIEW";
      case "scanning":
        return "NEURAL HEURISTIC SCAN // ACTIVE";
      case "idle":
      default:
        return "SECURITY CORE // STANDBY";
    }
  };

  return (
    <div className="absolute inset-0 pointer-events-none z-20 flex flex-col justify-between p-4 sm:p-5 select-none font-mono">
      {/* Top Header Telemetry Strip */}
      <div className="flex items-center justify-between w-full">
        {/* Status Badge */}
        <AnimatePresence mode="wait">
          <motion.div
            key={state}
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.28, ease: "easeOut" }}
            className={`inline-flex items-center gap-2 px-2.5 py-1 rounded-md text-[11px] font-semibold tracking-wider uppercase backdrop-blur-md border ${palette.uiBadgeBg} ${palette.uiBadgeBorder} ${palette.uiBadgeText}`}
          >
            <span
              className={`w-2 h-2 rounded-full ${palette.uiDot} ${
                state === "scanning" ? "animate-ping" : ""
              }`}
            />
            <span>{getBadgeLabel(state)}</span>
          </motion.div>
        </AnimatePresence>

        {/* System Watermark */}
        <div className="hidden sm:flex items-center gap-1.5 text-[10px] tracking-widest text-slate-500 dark:text-slate-400/80 uppercase font-medium">
          <span className="w-1.5 h-1.5 rounded-full bg-slate-400 dark:bg-slate-600" />
          <span>ZERO-TRUST SENTINEL // CORE-V4</span>
        </div>
      </div>

      {/* Optical Corner Crosshairs */}
      <div className="w-full flex items-center justify-between text-[11px] text-slate-400/60 dark:text-slate-600/70 font-mono select-none">
        <div className="flex items-center gap-2">
          <span>+</span>
          <span className="text-[9px] tracking-widest hidden sm:inline opacity-60">
            OPTIC_REF: 45.2°
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[9px] tracking-widest hidden sm:inline opacity-60">
            LAYER: PHYSICAL_GLASS
          </span>
          <span>+</span>
        </div>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// MAIN EXPORTED COMPONENT: Scanner3D
// Adapts flawlessly to Light (#F0F4F8) and Dark (#020617) themes with zero hydration bugs.
// ────────────────────────────────────────────────────────────────────────────
export interface Scanner3DProps {
  state?: ScanState;
  className?: string;
  showTelemetry?: boolean;
}

export function Scanner3D({
  state = "idle",
  className = "",
  showTelemetry = true,
}: Scanner3DProps) {
  const { resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  // Guarantee hydration safety: client theme is only evaluated after mount
  useEffect(() => {
    setMounted(true);
  }, []);

  const isDark = mounted ? resolvedTheme !== "light" : true;
  const palette = isDark
    ? PALETTE_DARK[state] || PALETTE_DARK.idle
    : PALETTE_LIGHT[state] || PALETTE_LIGHT.idle;

  return (
    <div
      className={`relative w-full h-full overflow-hidden transition-colors duration-700 ${
        isDark ? "bg-transparent" : "bg-[#F0F4F8]/40"
      } ${className}`}
    >
      {/* 1. HUD Telemetry Overlay (Pointer-Events-None) */}
      {showTelemetry && (
        <EnterpriseTelemetryOverlay state={state} palette={palette} />
      )}

      {/* 2. R3F WebGL 3D Canvas */}
      {mounted && (
        <Canvas
          camera={{ position: [0, 0, 4.4], fov: 46 }}
          gl={{
            antialias: true,
            alpha: true,
            powerPreference: "high-performance",
          }}
          style={{ background: "transparent" }}
          dpr={[1, 2]}
        >
          <Scene state={state} isDark={isDark} palette={palette} />
        </Canvas>
      )}
    </div>
  );
}

export default Scanner3D;