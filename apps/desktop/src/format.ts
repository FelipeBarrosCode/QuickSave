// SPDX-License-Identifier: GPL-3.0-only
export function folderName(path: string): string {
  const parts = path.split(/[\\/]/).filter(Boolean)
  return parts[parts.length - 1] || path
}

export function bytes(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return '—'
  if (value === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1)
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: index > 0 ? 1 : 0 }).format(value / 1024 ** index)} ${units[index]}`
}

export function date(value: string | null, compact = false): string {
  if (!value) return 'Date not reported'
  const parsed = new Date(value)
  if (!Number.isFinite(parsed.getTime())) return 'Date not reported'
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    ...(compact ? {} : { year: 'numeric', hour: '2-digit', minute: '2-digit' }),
  }).format(parsed)
}

export function number(value: number | null): string {
  return value === null ? '—' : new Intl.NumberFormat().format(value)
}
