// ============================================================
// Shared UI components – the single source of truth for all
// visual building blocks used across LogSentry SIEM.
// Upgraded with Luxury Creamy Palette & Modern Polish
// ============================================================

import { type ReactNode, useEffect, useState } from 'react';
import { CheckCircle2, XCircle, AlertTriangle, Clock } from 'lucide-react';

// ── SeverityBadge ─────────────────────────────────────────
interface SeverityBadgeProps {
  severity: string;
  size?: 'sm' | 'md';
}
export function SeverityBadge({ severity, size = 'md' }: SeverityBadgeProps) {
  const map: Record<string, string> = {
    CRITICAL: 'bg-rose-50 text-rose-700 border-rose-200/80 dark:bg-rose-500/15 dark:text-rose-300 dark:border-rose-500/30',
    HIGH:     'bg-orange-50 text-orange-700 border-orange-200/80 dark:bg-orange-500/15 dark:text-orange-300 dark:border-orange-500/30',
    MEDIUM:   'bg-amber-50 text-amber-700 border-amber-200/80 dark:bg-amber-500/15 dark:text-amber-300 dark:border-amber-500/30',
    LOW:      'bg-indigo-50 text-indigo-700 border-indigo-200/80 dark:bg-indigo-500/15 dark:text-indigo-300 dark:border-indigo-500/30',
  };
  const px = size === 'sm' ? 'px-2 py-0.5 text-[10px]' : 'px-2.5 py-1 text-xs';
  return (
    <span className={`${px} rounded-full font-bold uppercase tracking-wider border shadow-2xs ${map[severity] || 'bg-stone-100 text-stone-700 border-stone-200'}`}>
      {severity}
    </span>
  );
}

// ── StatusBadge ───────────────────────────────────────────
interface StatusBadgeProps { status: string }
export function StatusBadge({ status }: StatusBadgeProps) {
  const map: Record<string, { cls: string; label: string }> = {
    open:           { cls: 'bg-rose-50 text-rose-700 border-rose-200/80 dark:bg-rose-500/15 dark:text-rose-300 dark:border-rose-500/30',     label: 'Open' },
    investigating:  { cls: 'bg-amber-50 text-amber-700 border-amber-200/80 dark:bg-amber-500/15 dark:text-amber-300 dark:border-amber-500/30', label: 'Investigating' },
    assigned:       { cls: 'bg-indigo-50 text-indigo-700 border-indigo-200/80 dark:bg-indigo-500/15 dark:text-indigo-300 dark:border-indigo-500/30', label: 'Assigned' },
    resolved:       { cls: 'bg-emerald-50 text-emerald-700 border-emerald-200/80 dark:bg-emerald-500/15 dark:text-emerald-300 dark:border-emerald-500/30', label: 'Resolved' },
    false_positive: { cls: 'bg-stone-100 text-stone-600 border-stone-200/80 dark:bg-slate-700/30 dark:text-slate-300 dark:border-slate-600',   label: 'False Positive' },
  };
  const cfg = map[status?.toLowerCase()] || map.open;
  return (
    <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold border shadow-2xs ${cfg.cls}`}>
      {cfg.label}
    </span>
  );
}

// ── StatCard ──────────────────────────────────────────────
interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: ReactNode;
  colorClass?: string;
  trend?: { value: number; label: string };
  onClick?: () => void;
}
export function StatCard({ title, value, subtitle, icon, colorClass = '', trend, onClick }: StatCardProps) {
  return (
    <div
      onClick={onClick}
      className={`bg-[var(--bg-card)] rounded-2xl p-5 border border-[var(--border-default)] flex items-start justify-between shadow-xs transition-all duration-200 hover:border-[var(--border-hover)] hover:shadow-md hover:-translate-y-0.5 ${
        onClick ? 'cursor-pointer' : ''
      }`}
    >
      <div className="min-w-0 flex-1">
        <p className="text-[11px] text-[var(--text-muted)] font-bold uppercase tracking-wider mb-1.5">{title}</p>
        <p className="text-3xl font-extrabold text-[var(--text-primary)] leading-none tracking-tight">
          <AnimatedCounter value={value} duration={1000} />
        </p>
        {subtitle && <p className="text-xs text-[var(--text-muted)] mt-2 leading-tight">{subtitle}</p>}
        {trend && (
          <div className="mt-2 flex items-center gap-1.5">
            <span className={`text-[11px] font-bold px-1.5 py-0.2 rounded-md ${
              trend.value >= 0
                ? 'bg-red-50 text-red-700 border border-red-200 dark:bg-red-950 dark:text-red-400'
                : 'bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950 dark:text-emerald-400'
            }`}>
              {trend.value >= 0 ? '▲' : '▼'} {Math.abs(trend.value)}%
            </span>
            <span className="text-[10px] text-[var(--text-muted)]">{trend.label}</span>
          </div>
        )}
      </div>
      <div className={`p-3.5 rounded-xl shrink-0 ml-3 shadow-2xs ${colorClass}`}>{icon}</div>
    </div>
  );
}

// ── ChartCard ─────────────────────────────────────────────
interface ChartCardProps {
  title: string;
  subtitle?: string;
  children: ReactNode;
  action?: ReactNode;
}
export function ChartCard({ title, subtitle, children, action }: ChartCardProps) {
  return (
    <div className="bg-[var(--bg-card)] rounded-2xl border border-[var(--border-default)] shadow-xs overflow-hidden transition-all duration-200 hover:border-[var(--border-hover)]">
      <div className="flex items-center justify-between px-6 py-4.5 border-b border-[var(--border-subtle)] bg-[var(--bg-card-subtle)]/40">
        <div>
          <h3 className="text-sm font-bold text-[var(--text-primary)]">{title}</h3>
          {subtitle && <p className="text-xs text-[var(--text-muted)] mt-0.5">{subtitle}</p>}
        </div>
        {action && <div>{action}</div>}
      </div>
      <div className="p-6">{children}</div>
    </div>
  );
}

// ── HealthCard ────────────────────────────────────────────
interface HealthCardProps {
  name: string;
  status: 'healthy' | 'degraded' | 'down' | 'unknown';
  metric?: string;
  detail?: string;
  uptime?: number | null;
}
export function HealthCard({ name, status, metric, detail, uptime }: HealthCardProps) {
  const cfg = {
    healthy:  { dot: 'bg-emerald-500', text: 'text-emerald-700 dark:text-emerald-400', label: 'Operational', border: 'border-emerald-200 dark:border-emerald-800' },
    degraded: { dot: 'bg-amber-500',   text: 'text-amber-700 dark:text-amber-400',     label: 'Degraded',    border: 'border-amber-200 dark:border-amber-800' },
    down:     { dot: 'bg-red-500',     text: 'text-red-700 dark:text-red-400',         label: 'Down',         border: 'border-red-200 dark:border-red-800' },
    unknown:  { dot: 'bg-stone-400',   text: 'text-stone-600 dark:text-stone-400',     label: 'Unknown',      border: 'border-stone-200 dark:border-stone-700' },
  }[status];

  return (
    <div className={`bg-[var(--bg-card)] rounded-2xl p-5 border shadow-xs ${cfg.border}`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-bold text-[var(--text-primary)]">{name}</span>
        <span className={`flex items-center gap-1.5 text-xs font-semibold px-2 py-0.5 rounded-full bg-[var(--bg-card-subtle)] ${cfg.text}`}>
          <span className={`w-2 h-2 rounded-full ${cfg.dot} ${status === 'healthy' ? 'animate-pulse' : ''}`} />
          {cfg.label}
        </span>
      </div>
      {metric && <p className="text-xl font-extrabold text-[var(--text-primary)] mb-1">{metric}</p>}
      {detail && <p className="text-xs text-[var(--text-muted)]">{detail}</p>}
      {uptime !== undefined && uptime !== null && (
        <div className="mt-4 pt-3 border-t border-[var(--border-subtle)]">
          <div className="flex justify-between text-[11px] text-[var(--text-muted)] mb-1.5 font-medium">
            <span>Rolling Uptime</span>
            <span className="font-mono font-bold text-[var(--text-primary)]">{uptime}%</span>
          </div>
          <div className="h-2 bg-[var(--bg-card-subtle)] rounded-full overflow-hidden border border-[var(--border-subtle)]">
            <div
              className={`h-full rounded-full transition-all duration-700 ${
                status === 'healthy' ? 'bg-emerald-500' : status === 'degraded' ? 'bg-amber-500' : 'bg-red-500'
              }`}
              style={{ width: `${uptime}%` }}
            />
          </div>
        </div>
      )}
    </div>
  );
}

// ── MetricBar ─────────────────────────────────────────────
interface MetricBarProps {
  label: string;
  value: number;
  max?: number;
  unit?: string;
  color?: string;
}
export function MetricBar({ label, value, max = 100, unit = '%', color = 'bg-blue-600' }: MetricBarProps) {
  if (value === null || value === undefined) {
    return (
      <div>
        <div className="flex justify-between text-xs mb-1.5">
          <span className="text-[var(--text-muted)] font-medium">{label}</span>
          <span className="font-semibold text-[var(--text-faint)]">Unavailable</span>
        </div>
        <div className="h-2 bg-[var(--bg-card-subtle)] rounded-full overflow-hidden border border-[var(--border-subtle)]" />
      </div>
    );
  }

  const pct = Math.min((value / max) * 100, 100);
  const danger = pct > 80;
  const warn   = pct > 60;
  const barColor = danger ? 'bg-red-500' : warn ? 'bg-amber-500' : color;
  return (
    <div>
      <div className="flex justify-between text-xs mb-1.5">
        <span className="text-[var(--text-secondary)] font-medium">{label}</span>
        <span className="font-mono font-bold text-[var(--text-primary)]">{value}{unit}</span>
      </div>
      <div className="h-2 bg-[var(--bg-card-subtle)] rounded-full overflow-hidden border border-[var(--border-subtle)]">
        <div className={`h-full rounded-full transition-all duration-700 ${barColor}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

// ── SkeletonRow ───────────────────────────────────────────
export function SkeletonRow({ cols = 5 }: { cols?: number }) {
  return (
    <tr className="animate-pulse border-b border-[var(--border-subtle)]">
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-5 py-4">
          <div className="h-3.5 bg-[var(--border-subtle)] rounded-md w-3/4" />
        </td>
      ))}
    </tr>
  );
}

// ── EmptyState ────────────────────────────────────────────
interface EmptyStateProps { icon: ReactNode; title: string; desc: string; action?: ReactNode }
export function EmptyState({ icon, title, desc, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center px-4">
      <div className="p-5 bg-[var(--bg-card-subtle)] rounded-2xl border border-[var(--border-default)] text-[var(--text-muted)] mb-4 shadow-2xs">
        {icon}
      </div>
      <h3 className="text-base font-bold text-[var(--text-primary)]">{title}</h3>
      <p className="text-sm text-[var(--text-muted)] mt-1.5 max-w-sm leading-relaxed">{desc}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

// ── Timeline component ────────────────────────────────────
interface TimelineItem { time: string; event: string; detail?: string; type?: 'alert' | 'info' | 'success' | 'warning' }
export function Timeline({ items }: { items: TimelineItem[] }) {
  const icons: Record<string, ReactNode> = {
    alert:   <AlertTriangle className="w-3.5 h-3.5 text-red-600 dark:text-red-400" />,
    warning: <Clock className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />,
    success: <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />,
    info:    <div className="w-2 h-2 bg-blue-600 dark:bg-blue-400 rounded-full" />,
  };
  return (
    <div className="space-y-0">
      {items.map((item, i) => (
        <div key={i} className="flex gap-3.5 relative">
          <div className="flex flex-col items-center">
            <div className="w-7 h-7 rounded-full bg-[var(--bg-card-subtle)] border border-[var(--border-default)] flex items-center justify-center shrink-0 z-10 shadow-2xs">
              {icons[item.type || 'info']}
            </div>
            {i < items.length - 1 && <div className="w-px flex-1 bg-[var(--border-default)] mt-1" />}
          </div>
          <div className="pb-5 min-w-0 flex-1">
            <p className="text-xs font-bold text-[var(--text-primary)]">{item.event}</p>
            {item.detail && <p className="text-xs text-[var(--text-secondary)] mt-1 leading-relaxed">{item.detail}</p>}
            <p className="text-[11px] text-[var(--text-muted)] font-mono mt-1">{item.time}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Toast ─────────────────────────────────────────────────
interface ToastProps { message: string; type: 'success' | 'error' | 'info'; onClose: () => void }
export function Toast({ message, type, onClose }: ToastProps) {
  const cfg = {
    success: 'bg-emerald-50 dark:bg-emerald-950/80 border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300',
    error:   'bg-red-50 dark:bg-red-950/80 border-red-200 dark:border-red-800 text-red-800 dark:text-red-300',
    info:    'bg-blue-50 dark:bg-blue-950/80 border-blue-200 dark:border-blue-800 text-blue-800 dark:text-blue-300',
  }[type];
  return (
    <div className={`fixed bottom-6 right-6 z-[9999] flex items-center gap-3 px-5 py-3.5 rounded-2xl border shadow-xl backdrop-blur-md ${cfg} animate-slide-up`}>
      {type === 'success' && <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600" />}
      {type === 'error' && <XCircle className="w-4 h-4 shrink-0 text-red-600" />}
      <span className="text-sm font-semibold">{message}</span>
      <button onClick={onClose} className="ml-2 text-current opacity-60 hover:opacity-100 text-lg leading-none">&times;</button>
    </div>
  );
}

// ── Tooltip ───────────────────────────────────────────────
export function Tooltip({ text, children }: { text: string; children: ReactNode }) {
  return (
    <div className="relative group inline-flex">
      {children}
      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-1.5 bg-stone-900 border border-stone-800 text-stone-100 text-xs rounded-xl whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none shadow-xl z-50">
        {text}
        <div className="absolute top-full left-1/2 -translate-x-1/2 border-4 border-transparent border-t-stone-900" />
      </div>
    </div>
  );
}

// ── ProgressRing ──────────────────────────────────────────
export function ProgressRing({ value, size = 64, stroke = 5, color = '#2563eb' }: { value: number; size?: number; stroke?: number; color?: string }) {
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ - (value / 100) * circ;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--border-subtle)" strokeWidth={stroke} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke}
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.16, 1, 0.3, 1)' }}
      />
    </svg>
  );
}

// ── AnimatedCounter ───────────────────────────────────────
export function AnimatedCounter({ value, duration = 1000 }: { value: number | string; duration?: number }) {
  const [count, setCount] = useState(0);
  const target = typeof value === 'number' ? value : parseFloat(value as string) || 0;
  const isString = typeof value === 'string' && isNaN(Number(value));

  useEffect(() => {
    if (isString) return;
    let startTimestamp: number;
    const step = (timestamp: number) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / duration, 1);
      setCount(Math.floor(progress * target));
      if (progress < 1) window.requestAnimationFrame(step);
    };
    window.requestAnimationFrame(step);
  }, [target, duration, isString]);

  if (isString) return <span>{value}</span>;
  return <span>{count.toLocaleString()}</span>;
}
