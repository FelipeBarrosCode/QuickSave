// SPDX-License-Identifier: GPL-3.0-only
import { useEffect, useRef, useState } from 'react'
import { MAX_SELECTION, safeError, type FileItem, type PageResult, type SoftwareRoot } from './api'
import { bytes, number } from './format'
import { Icon } from './Icon'
import { Button, InlineError } from './ui'

export function FileBrowser({ load, label, transferLabel, onTransfer, disabled, roots }: {
  load: (cursor?: string) => Promise<PageResult<FileItem>>
  label: string; transferLabel: 'Upload' | 'Download'; disabled: boolean
  onTransfer: (fileIds: string[]) => Promise<void>
  roots?: SoftwareRoot[]
}) {
  const [page, setPage] = useState<PageResult<FileItem> | null>(null)
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined])
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [round, setRound] = useState(0)
  const loader = useRef(load)
  loader.current = load
  const cursor = cursors[cursors.length - 1]
  function refresh() {
    setCursors([undefined]); setSelected(new Set()); setRound((value) => value + 1)
  }
  useEffect(() => {
    let disposed = false
    setLoading(true)
    setError(null)
    setPage(null)
    void loader.current(cursor).then((next) => {
      if (!disposed) setPage(next)
    }).catch((reason) => {
      if (!disposed) setError(safeError(reason))
    }).finally(() => { if (!disposed) setLoading(false) })
    return () => { disposed = true }
  }, [cursor, round])
  function toggle(id: string, checked: boolean) {
    setSelected((previous) => {
      const next = new Set(previous)
      if (checked && next.size < MAX_SELECTION) next.add(id)
      else if (!checked) next.delete(id)
      return next
    })
  }
  function role(file: FileItem): string | undefined {
    const root = roots?.find((item) => item.id === file.rootId)
    return file.role || root?.roles?.join(', ') || root?.role
  }
  return <section className="file-browser" aria-label={label} aria-busy={loading}>
    <div className="file-toolbar"><strong>Files</strong>
      <span className="muted">{number(selected.size)} selected</span>
      {selected.size > 0 && <button className="text-button" type="button" onClick={() => setSelected(new Set())}>Clear selection</button>}
    </div>
    {loading && <p className="empty-line" role="status">Loading files…</p>}
    {error && <InlineError message={error} onRetry={refresh} />}
    {page && <>
      {page.items.length === 0 ? <p className="empty-line">No files reported.</p>
        : <ul className="file-list">{page.items.map((file) => <li key={file.id} className="file-row">
          <input type="checkbox" aria-label={`Select ${file.path}`} checked={selected.has(file.id)}
            disabled={disabled || file.directory || (!selected.has(file.id) && selected.size >= MAX_SELECTION)}
            onChange={(event) => toggle(file.id, event.target.checked)} />
          <Icon name={file.directory ? 'folder' : 'file'} size={18} />
          <span className="file-path truncate" title={file.path}>{file.path}</span>
          {role(file) && <span className="file-role muted" title={role(file)}>{role(file)}</span>}
          <span className="file-size">{file.directory ? 'Folder' : bytes(file.size)}</span>
        </li>)}</ul>}
      <div className="pagination"><span className="muted">Page {cursors.length}</span>
        <Button variant="ghost" disabled={loading || cursors.length === 1}
          onClick={() => setCursors((previous) => previous.slice(0, -1))}>Previous</Button>
        <Button variant="ghost" disabled={loading || !page.nextCursor || cursors.length >= 1_000}
          onClick={() => {
            if (page.nextCursor && !cursors.includes(page.nextCursor)) {
              setCursors((previous) => [...previous, page.nextCursor!])
            } else setError('The native file cursor did not advance. Refresh the file list.')
          }}>Next</Button>
      </div>
    </>}
    <div className="file-transfer">
      <Button icon={transferLabel === 'Upload' ? 'backup' : 'download'} variant="secondary"
        disabled={disabled || loading || !!error || selected.size === 0}
        onClick={() => { void onTransfer([...selected]) }}>
        {transferLabel} selected{selected.size > 0 ? ` (${selected.size})` : ''}
      </Button>
      {selected.size >= MAX_SELECTION && <span className="muted">512-file selection limit.</span>}
    </div>
  </section>
}
