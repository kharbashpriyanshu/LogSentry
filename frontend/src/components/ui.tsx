// ============================================================
// Shared UI components – the single source of truth for all
// visual building blocks used across LogSentry pages.
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
    CRITICAL: 'bg-red-500/20 text-red-400 border border-red-500/40',
    HIGH:     'bg-orange-500/20 text-orange-400 border border-orange-500/40',
    MEDIUM:   'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40',
    LOW:      'bg-blue-500/20 text-blue-400 border border-blue-500/40',
  };
  const px = size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2.5 py-1 text-xs';
  return (
    <span className={`${px} rounded-full font-semibold uppercase tracking-wide ${map[severity] || 'bg-slate-700 text-slate-300'}`}>
      {severity}
    </span>
  );
}

// ── StatusBadge ───────────────────────────────────────────
interface StatusBadgeProps { status: string }
export function StatusBadge({ status }: StatusBadgeProps) {
  const map: Record<string, { cls: string; label: string }> = {
    open:           { cls: 'bg-red-500/15 text-red-400 border-red-500/30',     label: 'Open' },
    investigating:  { cls: 'bg-amber-500/15 text-amber-400 border-amber-500/30', label: 'Investigating' },
    assigned:       { cls: 'bg-blue-500/15 text-blue-400 border-blue-500/30', label: 'Assigned' },
    resolved:       { cls: 'bg-green-500/15 text-green-400 border-green-500/30', label: 'Resolved' },
    false_positive: { cls: 'bg-slate-500/15 text-slate-400 border-slate-500/30',   label: 'False Positive' },
  };
  const cfg = map[status?.toLowerCase()] || map.open;
  return (
    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${cfg.cls}`}>
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
      className={`bg-[#1e293b] rounded-xl p-5 border border-slate-700/80 flex items-start justify-between shadow-lg transition-all duration-200 hover:border-slate-500 hover:shadow-xl hover:-translate-y-0.5 ${onClick ? 'cursor-pointer' : ''}`}
    >
      <div className="min-w-0">
        <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-widest mb-1">{title}</p>
        <p className="text-3xl font-extrabold text-slate-50 leading-none"><AnimatedCounter value={value} duration={1200} /></p>
        {subtitle && <p className="text-[11px] text-slate-500 mt-1.5 leading-tight">{subtitle}</p>}
        {trend && (
          <p className={`text-[10px] mt-1.5 font-semibold ${trend.value >= 0 ? 'text-red-400' : 'text-green-400'}`}>
            {trend.value >= 0 ? '▲' : '▼'} {Math.abs(trend.value)}% {trend.label}
          </p>
        )}
      </div>
      <div className={`p-3 rounded-lg shrink-0 ml-3 ${colorClass}`}>{icon}</div>
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
    <div className="bg-[#1e293b] rounded-xl border border-slate-700/80 overflow-hidden">
      <div className="flex items-center justify-between px-5 py-4 border-b border-slate-700/60">
        <div>
          <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
          {subtitle && <p className="text-[11px] text-slate-500 mt-0.5">{subtitle}</p>}
        </div>
        {action && <div>{action}</div>}
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

// ── HealthCard ────────────────────────────────────────────
interface HealthCardProps {
  name: string;
  status: 'healthy' | 'degraded' | 'down' | 'unknown';
  metric?: string;
  detail?: string;
  uptime?: number | null; // 0–100, or null when genuinely unavailable
}
export function HealthCard({ name, status, metric, detail, uptime }: HealthCardProps) {
  const cfg = {
    healthy:  { dot: 'bg-green-500',  text: 'text-green-400',  label: 'Operational', border: 'border-green-500/20' },
    degraded: { dot: 'bg-yellow-500', text: 'text-yellow-400', label: 'Degraded',    border: 'border-yellow-500/20' },
    down:     { dot: 'bg-red-500',    text: 'text-red-400',    label: 'Down',         border: 'border-red-500/20' },
    unknown:  { dot: 'bg-slate-500',  text: 'text-slate-400',  label: 'Unknown',      border: 'border-slate-600' },
  }[status];

  return (
    <div className={`bg-slate-800/40 rounded-xl p-4 border ${cfg.border}`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-semibold text-slate-200">{name}</span>
        <span className={`flex items-center gap-1.5 text-[11px] font-semibold ${cfg.text}`}>
          <span className={`w-2 h-2 rounded-full ${cfg.dot} ${status === 'healthy' ? 'animate-pulse' : ''}`} />
          {cfg.label}
        </span>
      </div>
      {metric && <p className="text-lg font-bold text-slate-100 mb-1">{metric}</p>}
      {detail && <p className="text-[11px] text-slate-500">{detail}</p>}
      {uptime !== undefined && (
        <div className="mt-3">
          <div className="flex justify-between text-[10px] text-slate-500 mb-1">
            <span>Uptime</span><span>{uptime}%</span>
          </div>
          <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${status === 'healthy' ? 'bg-green-500' : status === 'degraded' ? 'bg-yellow-500' : 'bg-red-500'}`}
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
export function MetricBar({ label, value, max = 100, unit = '%', color = 'bg-blue-500' }: MetricBarProps) {
  if (value === null) {
    return (
      <div>
        <div className="flex justify-between text-xs mb-1.5">
          <span className="text-slate-400">{label}</span>
          <span className="font-semibold text-slate-500">Unavailable</span>
        </div>
        <div className="h-2 bg-slate-800 rounded-full overflow-hidden" />
      </div>
    );
  }

  const pct = Math.min((value / max) * 100, 100);
  const danger = pct > 80;
  const warn   = pct > 60;
  const barColor = danger ? 'bg-red-500' : warn ? 'bg-yellow-500' : color;
  return (
    <div>
      <div className="flex justify-between text-xs mb-1.5">
        <span className="text-slate-400">{label}</span>
        <span className="font-semibold text-slate-200">{value}{unit}</span>
      </div>
      <div className="h-2 bg-slate-700/60 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all duration-700 ${barColor}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

// ── SkeletonRow ───────────────────────────────────────────
export function SkeletonRow({ cols = 5 }: { cols?: number }) {
  return (
    <tr className="animate-pulse">
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-3 bg-slate-700/60 rounded w-3/4" />
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
      <div className="p-5 bg-slate-800/60 rounded-2xl border border-slate-700 text-slate-500 mb-4">{icon}</div>
      <h3 className="text-base font-semibold text-slate-300">{title}</h3>
      <p className="text-sm text-slate-500 mt-1 max-w-xs leading-relaxed">{desc}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

// ── Timeline component ────────────────────────────────────
interface TimelineItem { time: string; event: string; detail?: string; type?: 'alert' | 'info' | 'success' | 'warning' }
export function Timeline({ items }: { items: TimelineItem[] }) {
  const icons: Record<string, ReactNode> = {
    alert:   <AlertTriangle className="w-3.5 h-3.5 text-red-400" />,
    warning: <Clock className="w-3.5 h-3.5 text-yellow-400" />,
    success: <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />,
    info:    <div className="w-2 h-2 bg-blue-400 rounded-full" />,
  };
  return (
    <div className="space-y-0">
      {items.map((item, i) => (
        <div key={i} className="flex gap-3 relative">
          <div className="flex flex-col items-center">
            <div className="w-6 h-6 rounded-full bg-slate-800 border border-slate-600 flex items-center justify-center shrink-0 z-10">
              {icons[item.type || 'info']}
            </div>
            {i < items.length - 1 && <div className="w-px flex-1 bg-slate-700/50 mt-0.5" />}
          </div>
          <div className="pb-4 min-w-0">
            <p className="text-xs font-semibold text-slate-200">{item.event}</p>
            {item.detail && <p className="text-[11px] text-slate-500 mt-0.5 leading-relaxed">{item.detail}</p>}
            <p className="text-[10px] text-slate-600 mt-0.5">{item.time}</p>
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
    success: 'bg-green-500/20 border-green-500/40 text-green-300',
    error:   'bg-red-500/20 border-red-500/40 text-red-300',
    info:    'bg-blue-500/20 border-blue-500/40 text-blue-300',
  }[type];
  return (
    <div className={`fixed bottom-6 right-6 z-[9999] flex items-center gap-3 px-5 py-3 rounded-xl border shadow-2xl backdrop-blur-sm ${cfg} animate-slide-up`}>
      {type === 'success' && <CheckCircle2 className="w-4 h-4 shrink-0" />}
      {type === 'error' && <XCircle className="w-4 h-4 shrink-0" />}
      <span className="text-sm font-medium">{message}</span>
      <button onClick={onClose} className="ml-2 text-current opacity-60 hover:opacity-100 text-lg leading-none">&times;</button>
    </div>
  );
}

// ── Tooltip ───────────────────────────────────────────────
export function Tooltip({ text, children }: { text: string; children: ReactNode }) {
  return (
    <div className="relative group inline-flex">
      {children}
      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2.5 py-1.5 bg-slate-900 border border-slate-700 text-slate-200 text-[11px] rounded-lg whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none shadow-xl z-50">
        {text}
        <div className="absolute top-full left-1/2 -translate-x-1/2 border-4 border-transparent border-t-slate-900" />
      </div>
    </div>
  );
}

// ── ProgressRing ──────────────────────────────────────────
export function ProgressRing({ value, size = 60, stroke = 5, color = '#3b82f6' }: { value: number; size?: number; stroke?: number; color?: string }) {
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ - (value / 100) * circ;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1e293b" strokeWidth={stroke} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke}
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        style={{ transition: 'stroke-dashoffset 0.8s ease' }}
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
  return <span>{count}</span>;
}
