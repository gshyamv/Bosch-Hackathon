import { ReactNode, useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, ChevronRight, Search, X } from "lucide-react";
import type { Evidence, Level } from "../api";

export const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(" ");

// ------------------------------------------------------------------ colour language (one meaning per colour)
export const LEVEL_STYLE: Record<string, string> = {
  Critical: "bg-red-50 text-red-700 ring-red-600/20",
  High: "bg-orange-50 text-orange-700 ring-orange-600/20",
  Medium: "bg-amber-50 text-amber-800 ring-amber-600/20",
  Low: "bg-sky-50 text-sky-700 ring-sky-600/20",
  Info: "bg-slate-50 text-slate-600 ring-slate-500/20",
};
export const LEVEL_DOT: Record<string, string> = {
  Critical: "bg-red-600", High: "bg-orange-500", Medium: "bg-amber-400", Low: "bg-sky-500", Info: "bg-slate-400",
};
export const LEVEL_HEX: Record<string, string> = {
  Critical: "#dc2626", High: "#f97316", Medium: "#fbbf24", Low: "#0ea5e9", Info: "#94a3b8",
};
const SEV_TO_LEVEL: Record<string, Level> = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low" };
const PRIO_LEVEL: Record<string, Level> = { P0: "Critical", P1: "High", P2: "Medium", P3: "Low" };

export function Badge({ children, className, title }: { children: ReactNode; className?: string; title?: string }) {
  return (
    <span title={title} className={cx("inline-flex items-center gap-1 whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset", className || "bg-slate-50 text-slate-600 ring-slate-500/20")}>
      {children}
    </span>
  );
}
export function LevelBadge({ level, score }: { level: string; score?: number }) {
  return (
    <Badge className={LEVEL_STYLE[level] || LEVEL_STYLE.Info}>
      <span className={cx("h-1.5 w-1.5 rounded-full", LEVEL_DOT[level] || LEVEL_DOT.Info)} />
      {level}{score !== undefined && <span className="tabular-nums opacity-70">{score}</span>}
    </Badge>
  );
}
export function SeverityBadge({ label }: { label: string }) {
  const lv = SEV_TO_LEVEL[label?.toUpperCase()] || "Info";
  return <Badge className={LEVEL_STYLE[lv]}>{label || "UNKNOWN"}</Badge>;
}
export function PriorityBadge({ priority, urgent }: { priority: string; urgent?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1">
      <Badge className={LEVEL_STYLE[PRIO_LEVEL[priority] || "Info"]}>{priority}</Badge>
      {urgent && <Badge className="bg-red-600 text-white ring-red-700">URGENT</Badge>}
    </span>
  );
}
export function NewBadge() {
  return <Badge className="bg-violet-50 text-violet-700 ring-violet-600/20">NEW</Badge>;
}
const STATUS_STYLE: Record<string, string> = {
  ok: "bg-emerald-50 text-emerald-700 ring-emerald-600/20", passed: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
  resolved: "bg-emerald-50 text-emerald-700 ring-emerald-600/20", approved: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
  verified: "bg-emerald-50 text-emerald-700 ring-emerald-600/20", approve: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
  failed: "bg-red-50 text-red-700 ring-red-600/20", rejected: "bg-red-50 text-red-700 ring-red-600/20",
  reject: "bg-red-50 text-red-700 ring-red-600/20", timeout: "bg-red-50 text-red-700 ring-red-600/20",
  partially_verified: "bg-amber-50 text-amber-800 ring-amber-600/20", partial: "bg-amber-50 text-amber-800 ring-amber-600/20",
  risk_accepted: "bg-amber-50 text-amber-800 ring-amber-600/20", accept_risk: "bg-amber-50 text-amber-800 ring-amber-600/20",
  request_changes: "bg-sky-50 text-sky-700 ring-sky-600/20", changes_requested: "bg-sky-50 text-sky-700 ring-sky-600/20",
  running: "bg-brand-50 text-brand-700 ring-brand-600/20",
};
export function StatusBadge({ status }: { status: string }) {
  return <Badge className={STATUS_STYLE[status] || undefined}>{(status || "-").replace(/_/g, " ")}</Badge>;
}

// ------------------------------------------------------------------ layout
export function Card({ title, subtitle, actions, children, className, pad = true }:
  { title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; pad?: boolean }) {
  return (
    <section className={cx("rounded-xl border border-slate-200 bg-white shadow-card", className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 px-5 py-3.5">
          <div className="min-w-0">
            {title && <h3 className="text-sm font-semibold text-slate-900">{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={pad ? "p-5" : ""}>{children}</div>
    </section>
  );
}

export function Stat({ label, value, hint, tone, icon }:
  { label: string; value: ReactNode; hint?: ReactNode; tone?: "red" | "orange" | "violet" | "green" | "brand"; icon?: ReactNode }) {
  const tones: Record<string, string> = {
    red: "text-red-600", orange: "text-orange-600", violet: "text-violet-600", green: "text-emerald-600", brand: "text-brand-600",
  };
  return (
    <div className="rounded-xl border border-slate-200 bg-white px-4 py-3.5 shadow-card">
      <div className="flex items-center justify-between text-xs font-medium text-slate-500">
        <span>{label}</span>{icon && <span className="text-slate-400">{icon}</span>}
      </div>
      <div className={cx("mt-1.5 text-2xl font-semibold tabular-nums tracking-tight text-slate-900", tone && tones[tone])}>{value}</div>
      {hint && <div className="mt-0.5 truncate text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-slate-900">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-slate-500">{description}</p>}
      </div>
      {actions}
    </div>
  );
}

export function Empty({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-300 bg-white px-6 py-14 text-center">
      {icon && <div className="mb-3 text-slate-400">{icon}</div>}
      <p className="text-sm font-medium text-slate-800">{title}</p>
      {children && <div className="mt-1 max-w-md text-sm text-slate-500">{children}</div>}
    </div>
  );
}

export function Callout({ tone = "info", children, icon }: { tone?: "info" | "warn" | "ok" | "error"; children: ReactNode; icon?: ReactNode }) {
  const s = {
    info: "border-brand-200 bg-brand-50 text-brand-900", warn: "border-amber-200 bg-amber-50 text-amber-900",
    ok: "border-emerald-200 bg-emerald-50 text-emerald-900", error: "border-red-200 bg-red-50 text-red-900",
  }[tone];
  return <div className={cx("flex gap-2.5 rounded-lg border px-3.5 py-2.5 text-sm", s)}>{icon}<div className="min-w-0">{children}</div></div>;
}

export function Button({ children, onClick, variant = "secondary", disabled, type = "button", className, title }:
  { children: ReactNode; onClick?: () => void; variant?: "primary" | "secondary" | "ghost" | "danger"; disabled?: boolean;
    type?: "button" | "submit"; className?: string; title?: string }) {
  const v = {
    primary: "bg-brand-600 text-white hover:bg-brand-700 shadow-sm disabled:bg-brand-400",
    secondary: "bg-white text-slate-700 ring-1 ring-inset ring-slate-300 hover:bg-slate-50",
    ghost: "text-slate-600 hover:bg-slate-100",
    danger: "bg-red-600 text-white hover:bg-red-700",
  }[variant];
  return (
    <button type={type} title={title} onClick={onClick} disabled={disabled}
      className={cx("inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60", v, className)}>
      {children}
    </button>
  );
}

export function LinkButton({ href, children, download }: { href: string; children: ReactNode; download?: boolean }) {
  return (
    <a href={href} target={download ? undefined : "_blank"} rel="noreferrer"
      className="inline-flex items-center gap-1.5 rounded-lg bg-white px-3 py-2 text-sm font-medium text-slate-700 ring-1 ring-inset ring-slate-300 transition hover:bg-slate-50">
      {children}
    </a>
  );
}

export function Toggle({ checked, onChange, label, disabled, hint }:
  { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean; hint?: string }) {
  return (
    <label title={hint} className={cx("flex cursor-pointer select-none items-center gap-2.5 text-sm", disabled && "cursor-not-allowed opacity-50")}>
      <button type="button" role="switch" aria-checked={checked} disabled={disabled} onClick={() => onChange(!checked)}
        className={cx("relative h-5 w-9 shrink-0 rounded-full transition", checked ? "bg-brand-600" : "bg-slate-300")}>
        <span className={cx("absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition", checked ? "left-[18px]" : "left-0.5")} />
      </button>
      <span className="text-slate-700">{label}</span>
    </label>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: ReactNode }[]; value: T; onChange: (t: T) => void }) {
  return (
    <div className="mb-5 flex gap-1 overflow-x-auto border-b border-slate-200">
      {tabs.map((t) => (
        <button key={t.id} onClick={() => onChange(t.id)}
          className={cx("-mb-px whitespace-nowrap border-b-2 px-3.5 py-2.5 text-sm font-medium transition",
            value === t.id ? "border-brand-600 text-brand-700" : "border-transparent text-slate-500 hover:text-slate-800")}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Segmented<T extends string>({ options, value, onChange }: { options: { id: T; label: ReactNode }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="inline-flex flex-wrap rounded-lg bg-slate-100 p-0.5">
      {options.map((o) => (
        <button key={o.id} type="button" onClick={() => onChange(o.id)}
          className={cx("rounded-md px-2.5 py-1 text-xs font-medium transition",
            value === o.id ? "bg-white text-slate-900 shadow-sm" : "text-slate-500 hover:text-slate-800")}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Chips<T extends string>({ options, value, onChange }: { options: T[]; value: T[]; onChange: (v: T[]) => void }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {options.map((o) => {
        const on = value.includes(o);
        return (
          <button key={o} type="button" onClick={() => onChange(on ? value.filter((x) => x !== o) : [...value, o])}
            className={cx("rounded-full px-2.5 py-1 text-xs font-medium ring-1 ring-inset transition",
              on ? "bg-ink-900 text-white ring-ink-900" : "bg-white text-slate-500 ring-slate-300 hover:text-slate-800")}>
            {o}
          </button>
        );
      })}
    </div>
  );
}

export function SearchInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <div className="relative">
      <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-slate-400" />
      <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder || "Search"}
        className="w-full rounded-lg border-0 py-2 pl-8 pr-3 text-sm ring-1 ring-inset ring-slate-300 placeholder:text-slate-400 focus:ring-2 focus:ring-brand-500 sm:w-64" />
    </div>
  );
}

export const inputCls = "w-full rounded-lg border-0 px-3 py-2 text-sm text-slate-900 ring-1 ring-inset ring-slate-300 placeholder:text-slate-400 focus:ring-2 focus:ring-brand-500";

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-slate-600" title={hint}>{label}</span>
      {children}
    </label>
  );
}

// ------------------------------------------------------------------ table (sortable, optional row click)
export interface Col<T> { key: string; label: string; render?: (r: T) => ReactNode; sort?: (r: T) => number | string; className?: string }

export function DataTable<T>({ rows, cols, onRow, rowKey, empty = "Nothing to show", maxHeight, selected }:
  { rows: T[]; cols: Col<T>[]; onRow?: (r: T) => void; rowKey: (r: T) => string; empty?: string; maxHeight?: number; selected?: string | null }) {
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null);
  const sorted = useMemo(() => {
    if (!sort) return rows;
    const c = cols.find((x) => x.key === sort.key);
    if (!c?.sort) return rows;
    return [...rows].sort((a, b) => {
      const x = c.sort!(a), y = c.sort!(b);
      return (x < y ? -1 : x > y ? 1 : 0) * sort.dir;
    });
  }, [rows, cols, sort]);
  if (!rows.length) return <p className="px-5 py-8 text-center text-sm text-slate-500">{empty}</p>;
  return (
    <div className="overflow-auto" style={maxHeight ? { maxHeight } : undefined}>
      <table className="min-w-full text-sm">
        <thead className="sticky top-0 z-10 bg-slate-50/95 backdrop-blur">
          <tr>
            {cols.map((c) => (
              <th key={c.key} onClick={() => c.sort && setSort((s) => ({ key: c.key, dir: s?.key === c.key && s.dir === -1 ? 1 : -1 }))}
                className={cx("whitespace-nowrap border-b border-slate-200 px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-slate-500",
                  c.sort && "cursor-pointer select-none hover:text-slate-800", c.className)}>
                <span className="inline-flex items-center gap-1">
                  {c.label}
                  {sort?.key === c.key && (sort.dir === 1 ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />)}
                </span>
              </th>
            ))}
            {onRow && <th className="w-8 border-b border-slate-200" />}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {sorted.map((r) => {
            const k = rowKey(r);
            return (
              <tr key={k} onClick={onRow ? () => onRow(r) : undefined}
                className={cx(onRow && "cursor-pointer hover:bg-slate-50", selected === k && "bg-brand-50/60")}>
                {cols.map((c) => (
                  <td key={c.key} className={cx("px-4 py-2.5 align-top text-slate-700", c.className)}>
                    {c.render ? c.render(r) : String((r as any)[c.key] ?? "")}
                  </td>
                ))}
                {onRow && <td className="px-2 py-2.5 text-slate-300"><ChevronRight className="h-4 w-4" /></td>}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ------------------------------------------------------------------ side drawer for details
export function Drawer({ open, onClose, title, subtitle, children }:
  { open: boolean; onClose: () => void; title: ReactNode; subtitle?: ReactNode; children: ReactNode }) {
  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-ink-950/40 backdrop-blur-[1px]" onClick={onClose} />
      <aside className="relative flex h-full w-full max-w-3xl flex-col bg-white shadow-2xl">
        <header className="flex items-start justify-between gap-4 border-b border-slate-200 px-6 py-4">
          <div className="min-w-0">
            <div className="text-base font-semibold text-slate-900">{title}</div>
            {subtitle && <div className="mt-1 text-sm text-slate-500">{subtitle}</div>}
          </div>
          <button onClick={onClose} className="rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700" aria-label="Close"><X className="h-5 w-5" /></button>
        </header>
        <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>
      </aside>
    </div>
  );
}

export function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-1 gap-1 py-2.5 sm:grid-cols-[170px_1fr] sm:gap-4">
      <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="min-w-0 text-sm text-slate-800">{children}</dd>
    </div>
  );
}

// ------------------------------------------------------------------ code, diffs, paths
export function Code({ children }: { children: ReactNode }) {
  return <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[12px] text-slate-800">{children}</code>;
}

export function Pre({ text, maxHeight = 360 }: { text: string; maxHeight?: number }) {
  return (
    <pre className="overflow-auto whitespace-pre-wrap break-all rounded-lg bg-ink-950 p-4 font-mono text-xs leading-relaxed text-slate-200" style={{ maxHeight }}>
      {text}
    </pre>
  );
}

export function Diff({ text, maxHeight = 420 }: { text: string; maxHeight?: number }) {
  return (
    <div className="overflow-auto rounded-lg border border-slate-200 bg-slate-50 font-mono text-xs leading-relaxed" style={{ maxHeight }}>
      {text.split("\n").map((l, i) => {
        const c = l.startsWith("+++") || l.startsWith("---") ? "text-slate-500 font-semibold"
          : l.startsWith("+") ? "bg-emerald-50 text-emerald-800"
          : l.startsWith("-") ? "bg-red-50 text-red-800"
          : l.startsWith("@@") ? "bg-brand-50 text-brand-700"
          : l.startsWith("#") ? "text-slate-500 italic" : "text-slate-700";
        return <div key={i} className={cx("whitespace-pre-wrap break-all px-3", c)}>{l || " "}</div>;
      })}
    </div>
  );
}

export function DepPath({ path }: { path: string[] }) {
  return (
    <div className="flex flex-wrap items-center gap-1 rounded-lg bg-slate-50 px-3 py-2 font-mono text-xs">
      {path.map((p, i) => (
        <span key={i} className="inline-flex items-center gap-1">
          {i > 0 && <ChevronRight className="h-3 w-3 text-slate-400" />}
          <span className={cx("rounded px-1.5 py-0.5", i === path.length - 1 ? "bg-red-100 text-red-800" : "bg-white text-slate-700 ring-1 ring-slate-200")}>{p}</span>
        </span>
      ))}
    </div>
  );
}

export function EvidenceLine({ e }: { e: Evidence }) {
  switch (e.type) {
    case "file":
      return <span><Code>{e.path}:{e.line}</Code> <span className="font-mono text-xs text-slate-600">{e.snippet}</span>{e.indicator && <span className="text-slate-500"> ({e.indicator})</span>}</span>;
    case "advisory":
      return (
        <span>
          <a className="font-medium text-brand-700 hover:underline" href={e.url} target="_blank" rel="noreferrer">{e.id}</a>
          {e.cves?.length ? <span className="text-slate-500"> ({e.cves.join(", ")})</span> : null}: {e.severity}
          {e.cvss_score != null && <>, CVSS {e.cvss_score}</>}
          {"fixed_in" in e && (e.fixed_in ? <>, fixed in <Code>{e.fixed_in}</Code></> : ", no fix published")}. <span className="text-slate-600">{e.summary}</span>
        </span>
      );
    case "change":
      return <span>lockfile change in <Code>{e.file}</Code>: {Object.entries(e.fields || {}).map(([k, v]: [string, any]) => (
        <span key={k} className="mr-2">{k}: <Code>{String(v.base)}</Code> → <Code>{String(v.head)}</Code></span>))}</span>;
    case "commit":
      return <span>commit <Code>{e.sha}</Code> by {e.author} &lt;{e.email}&gt;{e.first_time_author && <b className="text-red-700"> (first-time contributor)</b>}, {e.date}: “{e.message}”</span>;
    case "reference":
      return <span>{e.source}: {e.detail}</span>;
    default:
      return <span>{e.detail ?? JSON.stringify(e)}</span>;
  }
}

export function Spinner({ className }: { className?: string }) {
  return <span className={cx("inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-r-transparent", className)} />;
}

export const fmtTime = (t?: number | null) => (t ? new Date(t * 1000).toLocaleString() : "-");
export const fmtIso = (s?: string | null) => (s ? new Date(s).toLocaleString() : "-");
