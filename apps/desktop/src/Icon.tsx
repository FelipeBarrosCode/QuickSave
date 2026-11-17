// SPDX-License-Identifier: GPL-3.0-only
import type { CSSProperties } from 'react'

const paths = {
  overview: <><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></>,
  backup: <><path d="M4 15v4a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-4M12 3v12m-5-7 5-5 5 5" /></>,
  restore: <><path d="M3 10a9 9 0 1 1 1.8 7.4M3 4v6h6m3-3v5l3 2" /></>,
  shield: <><path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z" /><path d="m8.5 12 2.3 2.3 4.8-4.8" /></>,
  folder: <path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10H3V7Z" />,
  drive: <><path d="m5 4-3 11v5h20v-5L19 4H5Z" /><path d="M2 15h20M17 18h.01M13 18h.01" /></>,
  key: <><circle cx="8" cy="8" r="5" /><path d="m11.5 11.5 9 9m-3-3 3-3m-6 0 3-3" /></>,
  arrow: <path d="M4 12h16m-6-6 6 6-6 6" />,
  chevron: <path d="m9 5 7 7-7 7" />,
  check: <path d="m5 12 4 4L19 6" />,
  plus: <path d="M12 4v16M4 12h16" />,
  refresh: <><path d="M20 8a8 8 0 0 0-14-3L3 8m0-5v5h5m-4 8a8 8 0 0 0 14 3l3-3m0 5v-5h-5" /></>,
  info: <><circle cx="12" cy="12" r="9" /><path d="M12 11v6m0-10h.01" /></>,
  close: <path d="m6 6 12 12M6 18 18 6" />,
  warning: <><path d="m12 3 10 18H2L12 3Z" /><path d="M12 9v5m0 3h.01" /></>,
  monitor: <><rect x="2" y="3" width="20" height="14" rx="2" /><path d="M8 21h8m-4-4v4" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  file: <><path d="M14 2H4v20h16V8l-6-6Z" /><path d="M14 2v6h6M8 13h8m-8 4h5" /></>,
  lock: <><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2" /></>,
  sprout: <><path d="M12 21v-9M12 15C4 15 3 9 3 5c7 0 9 4 9 10Zm0-4c0-5 3-8 9-8 0 6-3 9-9 9" /></>,
  cloud: <><path d="M7 18a5 5 0 1 1 1-9 6 6 0 0 1 12 2 3.5 3.5 0 0 1-1.5 7H7Z" /><path d="m3 3 18 18" /></>,
  external: <><path d="M13 3h8v8m0-8L10 14m-1-9H3v16h16v-6" /></>,
} satisfies Record<string, React.ReactNode>

export type IconName = keyof typeof paths

export function Icon({ name, size = 20, className = '', style }: {
  name: IconName; size?: number; className?: string; style?: CSSProperties
}) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round"
      className={className} style={style} aria-hidden="true" focusable="false">
      {paths[name]}
    </svg>
  )
}
