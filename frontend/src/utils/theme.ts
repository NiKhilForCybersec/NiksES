/**
 * NiksES Theme Configuration
 * 
 * Centralized theme configuration.
 * All colors, spacing, and design tokens defined here.
 */

export const theme = {
  colors: {
    // Backgrounds
    bgPrimary: "#0d1117",
    bgSecondary: "#161b22",
    bgTertiary: "#21262d",
    bgElevated: "#30363d",
    
    // Text
    textPrimary: "#e6edf3",
    textSecondary: "#8b949e",
    textMuted: "#6e7681",
    
    // Borders
    borderDefault: "#30363d",
    borderMuted: "#21262d",
    
    // Risk Levels
    riskCritical: "#f85149",
    riskHigh: "#f0883e",
    riskMedium: "#d29922",
    riskLow: "#3fb950",
    riskInfo: "#58a6ff",
    
    // Verdicts
    verdictMalicious: "#f85149",
    verdictSuspicious: "#f0883e",
    verdictClean: "#3fb950",
    verdictUnknown: "#8b949e",
    
    // Accent
    accentPrimary: "#58a6ff",
    accentSuccess: "#3fb950",
    accentWarning: "#d29922",
    accentDanger: "#f85149",
  },
  
  spacing: {
    xs: "0.25rem",
    sm: "0.5rem",
    md: "1rem",
    lg: "1.5rem",
    xl: "2rem",
    xxl: "3rem",
  },
  
  borderRadius: {
    sm: "0.25rem",
    md: "0.375rem",
    lg: "0.5rem",
    xl: "0.75rem",
    full: "9999px",
  },
  
  fontSize: {
    xs: "0.75rem",
    sm: "0.875rem",
    base: "1rem",
    lg: "1.125rem",
    xl: "1.25rem",
    "2xl": "1.5rem",
    "3xl": "1.875rem",
  },
  
  fontFamily: {
    sans: "Inter, system-ui, sans-serif",
    mono: "JetBrains Mono, Fira Code, monospace",
  },
} as const;

// Tailwind class mappings for risk levels
export const riskColorClasses = {
  informational: "bg-blue-500/20 text-blue-400 border-blue-500/50",
  low: "bg-green-500/20 text-green-400 border-green-500/50",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/50",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/50",
  critical: "bg-red-500/20 text-red-400 border-red-500/50",
} as const;

// Tailwind class mappings for verdicts
export const verdictColorClasses = {
  clean: "bg-green-500/20 text-green-400",
  suspicious: "bg-yellow-500/20 text-yellow-400",
  malicious: "bg-red-500/20 text-red-400",
  unknown: "bg-gray-500/20 text-gray-400",
  error: "bg-gray-500/20 text-gray-500",
} as const;

// Risk level background colors for badges
export const riskBgColors = {
  informational: "bg-blue-500",
  low: "bg-green-500",
  medium: "bg-yellow-500",
  high: "bg-orange-500",
  critical: "bg-red-500",
} as const;

export type RiskLevel = keyof typeof riskColorClasses;
export type Verdict = keyof typeof verdictColorClasses;
