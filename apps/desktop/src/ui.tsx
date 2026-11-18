// SPDX-License-Identifier: GPL-3.0-only
import { useEffect, useId, useRef, type ButtonHTMLAttributes, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { Icon, type IconName } from './Icon'

export function Button({ children, icon, variant = 'primary', className = '', ...props }:
  ButtonHTMLAttributes<HTMLButtonElement> & {
    icon?: IconName; variant?: 'primary' | 'secondary' | 'ghost' | 'danger'; children: ReactNode
  }) {
  return <button type="button" className={`button button-${variant} ${className}`} {...props}>
    {icon && <Icon name={icon} size={18} />}{children}
  </button>
}

export function Dialog({ title, children, onClose, busy = false, sheet = false }: {
  title: string; children: ReactNode; onClose: () => void; busy?: boolean; sheet?: boolean
}) {
  const titleId = useId()
  const container = useRef<HTMLDivElement>(null)
  const previous = useRef<Element | null>(null)
  useEffect(() => {
    previous.current = document.activeElement
    container.current?.focus()
    return () => {
      if (previous.current instanceof HTMLElement && previous.current.isConnected) previous.current.focus()
    }
  }, [])
  return createPortal(<div className={`modal-backdrop ${sheet ? 'sheet-backdrop' : ''}`}
    onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onClose() }}>
    <div className={`dialog ${sheet ? 'dialog-sheet' : ''}`} role="dialog" aria-modal="true"
      aria-labelledby={titleId} tabIndex={-1} ref={container} onKeyDown={(event) => {
        if (event.key === 'Escape' && !busy) { event.stopPropagation(); onClose() }
        if (event.key !== 'Tab') return
         const controls = [...(container.current?.querySelectorAll<HTMLElement>(
           'button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),a[href],summary,[tabindex="0"]',
         ) ?? [])].filter((control) => {
           if (control.closest('[hidden]')) return false
           for (let parent = control.parentElement; parent && parent !== container.current; parent = parent.parentElement) {
             if (parent instanceof HTMLDetailsElement && !parent.open && parent.firstElementChild !== control) return false
           }
           return true
         })
        if (!controls?.length) { event.preventDefault(); return }
        const first = controls[0]
        const last = controls[controls.length - 1]
        if (event.shiftKey && (document.activeElement === first || document.activeElement === container.current)) {
          event.preventDefault(); last.focus()
        } else if (!event.shiftKey && (document.activeElement === last || document.activeElement === container.current)) {
          event.preventDefault(); first.focus()
        }
      }}>
      <header className="dialog-header"><h2 id={titleId}>{title}</h2>
        <button type="button" className="icon-button" onClick={onClose} disabled={busy} aria-label={`Close ${title.toLowerCase()}`}>
          <Icon name="close" />
        </button>
      </header>
      <div className="dialog-body">{children}</div>
    </div>
  </div>, document.body)
}

export function InlineError({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return <div className="inline-error" role="alert">
    <Icon name="warning" size={18} /><p>{message}</p>
    {onRetry && <Button variant="secondary" onClick={onRetry}>Retry</Button>}
  </div>
}
