// SPDX-License-Identifier: GPL-3.0-only
import { useEffect, useId, useRef, useState, type ButtonHTMLAttributes, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { Icon, type IconName } from './Icon'
import { bytes, date, folderName, number } from './format'
import { record, terminal, type NativeReport, type Snapshot } from './api'
import { useQuickSave, type QuickSave } from './useQuickSave'

type Page = 'overview' | 'backups' | 'restore' | 'capabilities'
type Confirmation = 'initialize' | 'backup' | 'restore' | null

const pages: { id: Page; label: string; icon: IconName }[] = [
  { id: 'overview', label: 'Overview', icon: 'overview' },
  { id: 'backups', label: 'Backups', icon: 'backup' },
  { id: 'restore', label: 'Restore', icon: 'restore' },
  { id: 'capabilities', label: 'Capabilities', icon: 'shield' },
]

function Button({ children, icon, variant = 'primary', className = '', ...props }:
  ButtonHTMLAttributes<HTMLButtonElement> & {
    icon?: IconName; variant?: 'primary' | 'secondary' | 'ghost'; children: ReactNode
  }) {
  return <button type="button" className={`button button-${variant} ${className}`} {...props}>
    {icon && <Icon name={icon} size={17} />}{children}
  </button>
}

function Brand() {
  return <div className="brand" aria-label="QuickSave">
    <span className="brand-mark" aria-hidden="true">
      <svg width="27" height="28" viewBox="0 0 27 28" fill="none">
        <path d="M5 3h7v7H5V3Zm10 0h7v7h-7V3ZM5 13h7v7H5v-7Z" fill="currentColor" />
        <path d="m15 13 9 9-5 5-9-9 5-5Z" fill="currentColor" />
      </svg>
    </span>
    <span>QuickSave<span className="brand-period">.</span></span>
  </div>
}

function PathField({ label, value, placeholder, hint, icon, onChoose, disabled, actionLabel = 'Browse' }: {
  label: string; value: string; placeholder: string; hint?: ReactNode;
  icon: IconName; onChoose: () => void; disabled: boolean; actionLabel?: string
}) {
  const id = useId()
  return <div className="path-field">
    <label htmlFor={id}>{label}</label>
    <div className={`path-control ${value ? 'has-path' : ''}`}>
      <Icon name={icon} size={19} />
      <input id={id} value={value} placeholder={placeholder} readOnly title={value || undefined}
        aria-describedby={hint ? `${id}-hint` : undefined} />
      <button type="button" onClick={onChoose} disabled={disabled} aria-label={`Choose ${label.toLowerCase()}`}>
        {actionLabel}<Icon name="chevron" size={14} />
      </button>
    </div>
    {hint && <p className="field-hint" id={`${id}-hint`}>{hint}</p>}
  </div>
}

function FolderIllustration() {
  return <div className="folder-illustration" aria-hidden="true">
    <span className="illustration-orbit orbit-one" /><span className="illustration-orbit orbit-two" />
    <svg viewBox="0 0 300 240" fill="none" className="folder-art">
      <path d="M64 68c0-7 6-13 13-13h54l17 16h70c7 0 13 6 13 13v99H64V68Z" fill="#9BB5A0" transform="rotate(-10 147 119)" />
      <rect x="88" y="51" width="117" height="122" rx="10" fill="#FAFBF5" transform="rotate(6 146 112)" />
      <path d="m110 83 64 7m-65 9 76 8m-78 9 55 6" stroke="#D2DCCB" strokeWidth="5" strokeLinecap="round" />
      <path d="M52 100c0-7 6-13 13-13h62l17 15h89c8 0 14 7 13 15l-10 72c-1 7-7 12-14 12H66c-8 0-14-6-14-14v-87Z" fill="#BAD77E" />
      <path d="M53 112h191" stroke="#E0EEBF" strokeWidth="2" />
      <path d="m151 128 27 10v19c0 20-27 33-27 33s-27-13-27-33v-19l27-10Z" fill="#284937" />
      <path d="m140 156 8 8 15-18" stroke="#D6E8B4" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M57 213h186" stroke="#91A18A" strokeOpacity=".25" strokeWidth="3" strokeLinecap="round" />
      <path d="m249 63 3-7 3 7 7 3-7 3-3 7-3-7-7-3 7-3Z" fill="#BAD77E" />
      <circle cx="49" cy="146" r="4" fill="#86A57A" /><circle cx="224" cy="39" r="3" fill="#86A57A" />
    </svg>
    <span className="illustration-label"><Icon name="lock" size={12} /> Local by design</span>
  </div>
}

function EmptySnapshots({ loaded, onConnect, selectable = false }: {
  loaded: boolean; onConnect: () => void; selectable?: boolean
}) {
  return <div className="empty-state">
    <span className="empty-icon"><Icon name={selectable ? 'restore' : 'folder'} size={28} /></span>
    <h3>{loaded ? 'A fresh start, ready for your files.' : 'Your versions will feel at home here.'}</h3>
    <p>{loaded
      ? 'This repository has no saved snapshots yet. Make your first folder backup to get started.'
      : 'Open a local repository with its recovery-key file to see your saved snapshots.'}</p>
    <Button variant="secondary" icon={loaded ? 'plus' : 'drive'} onClick={onConnect}>
      {loaded ? 'Create a backup' : 'Open a repository'}
    </Button>
  </div>
}

function SnapshotTable({ snapshots, onRestore, selectable = false, selectedId, onSelect }: {
  snapshots: Snapshot[]; onRestore?: (snapshot: Snapshot) => void;
  selectable?: boolean; selectedId?: string | null; onSelect?: (id: string) => void
}) {
  return <div className="table-scroll">
    <table className="snapshot-table">
      <thead><tr>
        <th scope="col">{selectable ? 'Select a snapshot' : 'Snapshot'}</th>
        <th scope="col">Files</th><th scope="col">Logical data</th>
        {!selectable && <th scope="col"><span className="sr-only">Actions</span></th>}
      </tr></thead>
      <tbody>{snapshots.map((snapshot) => <tr key={snapshot.id} className={selectedId === snapshot.id ? 'selected-row' : ''}>
        <td><div className="snapshot-cell">
          {selectable
            ? <input type="radio" name="snapshot" aria-label={`Restore snapshot ${snapshot.id}`}
              checked={selectedId === snapshot.id} onChange={() => onSelect?.(snapshot.id)} />
            : <span className="snapshot-icon"><Icon name="folder" size={19} /></span>}
          <div className="snapshot-name">
            {selectable
              ? <button className="snapshot-select" type="button" onClick={() => onSelect?.(snapshot.id)}>
                {date(snapshot.createdAt)}
              </button>
              : <strong>{date(snapshot.createdAt)}</strong>}
            <span className="snapshot-id" title={snapshot.id}>{snapshot.id}</span>
          </div>
        </div></td>
        <td>{number(snapshot.totalFiles)}</td><td>{bytes(snapshot.logicalBytes)}</td>
        {!selectable && <td><button className="table-action" type="button"
          onClick={() => onRestore?.(snapshot)} aria-label={`Restore snapshot ${snapshot.id}`}>
          Restore<Icon name="arrow" size={15} />
        </button></td>}
      </tr>)}</tbody>
    </table>
  </div>
}

function SnapshotBrowser({ model, selectedId, onSelect, onConnect }: {
  model: QuickSave; selectedId: string | null; onSelect: (id: string) => void; onConnect: () => void
}) {
  const [page, setPage] = useState(0)
  const pageSize = 6
  const pagesCount = Math.ceil(model.snapshots.length / pageSize)
  const visiblePage = Math.min(page, Math.max(0, pagesCount - 1))
  if (!model.snapshotsLoaded || model.snapshots.length === 0) {
    return <EmptySnapshots loaded={model.snapshotsLoaded} onConnect={onConnect} selectable />
  }
  return <>
    <SnapshotTable snapshots={model.snapshots.slice(visiblePage * pageSize, (visiblePage + 1) * pageSize)}
      selectedId={selectedId} onSelect={onSelect} selectable />
    <div className="table-pagination">
      <span>{number(model.snapshots.length)} snapshots · newest first</span>
      {pagesCount > 1 && <div>
        <button type="button" disabled={visiblePage === 0}
          onClick={() => setPage(visiblePage - 1)}>Previous</button>
        <span>{visiblePage + 1} / {pagesCount}</span>
        <button type="button" disabled={visiblePage >= pagesCount - 1}
          onClick={() => setPage(visiblePage + 1)}>Next</button>
      </div>}
    </div>
  </>
}

function OperationPanel({ model }: { model: QuickSave }) {
  const operation = model.operation
  if (!operation) return null
  const done = terminal(operation.state)
  const noun = operation.kind === 'initialize' ? 'Initialization' : operation.kind === 'backup' ? 'Backup' : 'Restore'
  const title = model.trackingPaused ? 'Operation status is unknown'
    : operation.state === 'queued' ? `${noun} accepted`
      : operation.state === 'running' ? `${noun} in progress`
        : operation.state === 'succeeded' ? `${model.operationRecovered ? `Previous ${noun.toLowerCase()}` : noun} completed`
          : operation.state === 'interrupted' ? `${noun} interrupted` : `${noun} failed`
  const result = record(operation.result)
  const snapshotId = typeof result?.snapshotId === 'string' ? result.snapshotId : null
  return <section className={`operation-panel operation-${model.trackingPaused ? 'paused' : operation.state}`}
    aria-label="Native operation" aria-live="polite">
    <span className={`operation-symbol ${!done && !model.trackingPaused ? 'is-spinning' : ''}`}>
      <Icon name={model.trackingPaused ? 'warning' : !done ? 'refresh' : operation.state === 'succeeded' ? 'check' : 'warning'} size={21} />
    </span>
    <div className="operation-copy">
      <div className="operation-heading"><strong>{title}</strong>
        <span className="badge">{model.trackingPaused ? 'Tracking paused' : operation.state}</span></div>
      <p>{model.trackingPaused || (
        operation.state === 'queued' ? 'Waiting for a native status update. Keep QuickSave open.'
          : operation.state === 'running' ? 'The native engine is working. It does not report percentage progress.'
            : operation.state === 'failed' || operation.state === 'interrupted' ? (operation.error || 'The native engine did not report successful completion. No automatic retry was started.')
              : model.operationRecovered ? 'This is a saved native operation receipt, not a current repository verification.'
                : operation.kind === 'backup' ? 'The native engine confirmed the snapshot commit.'
                  : operation.kind === 'restore' ? 'The native engine confirmed the restore.' : 'The native engine confirmed initialization.'
      )}</p>
      <div className="operation-meta">
        <span title={operation.id}>Job {operation.id.slice(0, 16)}</span>
        {model.operationRecovered && <span>Recovered from local history</span>}
        {operation.startedAt && <span>Started {date(operation.startedAt)}</span>}
        {operation.finishedAt && <span>Finished {date(operation.finishedAt)}</span>}
        {snapshotId && <span className="truncate" title={snapshotId}>Snapshot {snapshotId}</span>}
      </div>
    </div>
    {model.trackingPaused && <Button variant="secondary" icon="refresh" onClick={model.resumeTracking}>Resume tracking</Button>}
  </section>
}

function Overview({ model, navigate, onRestore }: {
  model: QuickSave; navigate: (page: Page) => void; onRestore: (id: string) => void
}) {
  const totalBytes = model.snapshotsLoaded && model.snapshots.every((snapshot) => snapshot.logicalBytes !== null)
    ? model.snapshots.reduce((sum, snapshot) => sum + (snapshot.logicalBytes ?? 0), 0) : null
  const safeTotal = totalBytes !== null && Number.isSafeInteger(totalBytes) ? totalBytes : null
  const latest = model.snapshotsLoaded ? model.snapshots[0] : undefined
  return <>
    <section className="hero">
      <div className="hero-copy">
        <span className="eyebrow"><span className="tiny-line" /> A little peace of mind</span>
        <h2>Your files.<br /><span>A safer place.</span></h2>
        <p>Keep a version of what matters, right where you choose.<br className="desktop-break" />
          Private, local folder backups. No account required.</p>
        <Button onClick={() => navigate('backups')}>Set up a backup<Icon name="arrow" size={18} /></Button>
        <span className="hero-footnote"><Icon name="lock" size={13} /> Your computer. Your repository. Your key.</span>
      </div>
      <FolderIllustration />
      <span className="hero-index" aria-hidden="true">QS / 001</span>
    </section>

    <section className="stats-grid" aria-label="Repository summary">
      <article className="stat-card">
        <div><span className="stat-label">Saved snapshots</span><Icon name="restore" size={19} /></div>
        <strong>{model.snapshotsLoaded ? number(model.snapshots.length) : '—'}</strong>
        <p>{model.snapshotsLoaded ? 'Versions in this repository' : 'Open a repository to see versions'}</p>
      </article>
      <article className="stat-card">
        <div><span className="stat-label">Logical file data</span><Icon name="drive" size={19} /></div>
        <strong>{bytes(safeTotal)}</strong>
        <p>Across snapshots, before deduplication</p>
      </article>
      <article className="stat-card">
        <div><span className="stat-label">Latest snapshot</span><Icon name="clock" size={19} /></div>
        <strong className="stat-date">{latest ? date(latest.createdAt, true) : '—'}</strong>
        <p>{latest ? date(latest.createdAt) : 'No snapshot date loaded'}</p>
      </article>
    </section>

    <div className="overview-grid">
      <section className="card recent-card">
        <div className="card-heading"><div><span className="eyebrow">A version to come back to</span><h2>Recent snapshots</h2></div>
          <button className="text-button" type="button" onClick={() => navigate('restore')}>View all<Icon name="arrow" size={15} /></button>
        </div>
        {model.snapshotsLoaded && model.snapshots.length > 0
          ? <SnapshotTable snapshots={model.snapshots.slice(0, 4)} onRestore={(snapshot) => onRestore(snapshot.id)} />
          : <EmptySnapshots loaded={model.snapshotsLoaded} onConnect={() => navigate('backups')} />}
        <div className="card-bottom-note"><Icon name="info" size={14} /> Snapshot history is additive. No automatic deletion.</div>
      </section>
      <aside className="overview-aside">
        <section className="card repository-summary">
          <div className="mini-heading"><span className="icon-tile"><Icon name="monitor" size={20} /></span>
            <span className="badge badge-neutral">This computer</span></div>
          <h3>Your local workspace</h3>
          <p>{model.verified ? 'A repository is open for this session.' : 'Connect a repository to get started.'}</p>
          <div className="workspace-detail"><span className={`status-dot ${model.verified ? 'status-ready' : ''}`} />
            <div><strong>{model.workspace.repository ? folderName(model.workspace.repository) : 'No repository selected'}</strong>
              <span>{model.verified ? 'Native repository opened' : model.workspace.repository ? 'Selected, not opened' : 'Only folders you choose are accessed'}</span></div>
          </div>
          <Button variant="secondary" icon="drive" onClick={() => navigate('backups')}>Manage repository</Button>
        </section>
        <section className="quiet-note">
          <Icon name="sprout" size={23} /><div><h3>Small footprint. Clear boundaries.</h3>
            <p>This pre-release backs up local folders. Cloud sync, scheduling, and application profiles are not available.</p>
            <button className="text-button" type="button" onClick={() => navigate('capabilities')}>What’s supported<Icon name="arrow" size={14} /></button>
          </div>
        </section>
      </aside>
    </div>
  </>
}

function BackupPage({ model, confirm, navigate }: {
  model: QuickSave; confirm: (kind: Confirmation) => void; navigate: (page: Page) => void
}) {
  const disabled = !model.native || model.working
  return <>
    <div className="page-intro"><span className="eyebrow">A place for what matters</span><h2>Make room for peace of mind.</h2>
      <p>Choose a local repository, bring your recovery key, and save a version of a folder.</p></div>
    <div className="workspace-grid">
      <div className="form-stack">
        <section className="card form-card">
          <div className="step-heading"><span className="step-number">01</span>
            <div><h3>Connect your repository</h3><p>A dedicated local folder where your encrypted snapshots live.</p></div>
            {model.verified && <span className="badge badge-green"><Icon name="check" size={12} /> Open</span>}
          </div>
          <div className="segmented" role="group" aria-label="Repository setup mode">
            <button type="button" aria-pressed={model.mode === 'existing'} disabled={model.working}
              onClick={() => model.changeMode('existing')}><Icon name="drive" size={15} />Use existing</button>
            <button type="button" aria-pressed={model.mode === 'new'} disabled={model.working}
              onClick={() => model.changeMode('new')}><Icon name="plus" size={15} />Create new</button>
          </div>
          <PathField label="Repository folder" value={model.workspace.repository} icon="drive"
            placeholder={model.mode === 'new' ? 'Choose an empty local folder' : 'Choose a QuickSave repository'}
            hint={model.mode === 'new'
              ? 'Choose an empty private folder (0700 on macOS/Linux, without extended ACLs). Existing permissions are not changed. Keep it outside the source.'
              : 'Keep the repository outside the source folder. No Land repositories are not compatible.'}
            onChoose={() => { void model.pick('repository') }} disabled={disabled} />
          <PathField label={model.mode === 'new' ? 'New recovery-key file' : 'Recovery-key file'} value={model.workspace.keyFile} icon="key"
            placeholder={model.mode === 'new' ? 'Choose where to save the new key' : 'Choose your existing external key file'}
            hint="Choose a path outside both the repository and source. Key contents never enter this interface."
            actionLabel={model.mode === 'new' ? 'Save as' : 'Browse'}
            onChoose={() => { void model.pick('keyFile') }} disabled={disabled} />
          <div className="form-actions">
            <Button icon={model.busy === 'initialize' || model.busy === 'snapshots' ? 'refresh' : model.mode === 'new' ? 'plus' : 'drive'}
              disabled={disabled || !model.pathsReady || (model.mode === 'new' ? !model.canWrite : !model.canRead)}
              onClick={() => model.mode === 'new' ? confirm('initialize') : void model.loadSnapshots()}>
              {model.busy === 'initialize' ? 'Repository request pending…' : model.busy === 'snapshots' ? 'Snapshot request pending…'
                : model.mode === 'new' ? 'Create repository' : model.verified ? 'Refresh snapshots' : 'Open repository'}
            </Button>
            <span>{model.mode === 'new' ? 'Native approval precedes repository and key creation.' : 'Native approval is required to read snapshot history.'}</span>
          </div>
        </section>

        <section className="card form-card">
          <div className="step-heading"><span className="step-number">02</span><div><h3>Choose what to keep</h3>
            <p>One folder, captured as a new snapshot. Existing versions stay untouched.</p></div></div>
          <PathField label="Source folder" value={model.workspace.source} icon="folder"
            placeholder="Choose a folder to back up" hint="Use a regular folder. Symlinks and unsupported filesystem entries are rejected."
            onChoose={() => { void model.pick('source') }} disabled={disabled} />
          <div className="inline-note"><Icon name="info" size={17} /><p><strong>Stable files, not a frozen application.</strong>
            {' '}Pause applications that write to this folder. Capture is not an application-wide atomic snapshot.</p></div>
          <div className="form-actions">
            <Button icon="backup" disabled={disabled || !model.canWrite || !model.verified || !model.workspace.source || model.mode !== 'existing'}
              onClick={() => confirm('backup')}>Back up this folder</Button>
            {!model.verified && <span>Open or create a repository first.</span>}
          </div>
        </section>
      </div>
      <aside className="guidance-stack">
        <section className="guidance-card">
          <span className="guidance-icon"><Icon name="key" size={27} /></span>
          <span className="eyebrow">Yours to keep safe</span><h3>A small file.<br />An important key.</h3>
          <p>Your recovery-key file unlocks your repository. QuickSave has no account reset and no spare copy.</p>
          <ul className="check-list"><li><Icon name="check" size={16} />Keep a separate, secure copy.</li>
            <li><Icon name="check" size={16} />Never place it in your source.</li>
            <li><Icon name="check" size={16} />Keep it outside the repository.</li></ul>
          <div className="guidance-footer"><Icon name="lock" size={15} /> Only its path reaches the interface.</div>
        </section>
        <section className="card help-card"><Icon name="restore" size={23} /><h3>Coming back is part of the plan.</h3>
          <p>Restore a saved snapshot into a separate, empty folder. Existing files are not overwritten.</p>
          <button className="text-button" type="button" onClick={() => navigate('restore')}>Go to restore<Icon name="arrow" size={15} /></button>
        </section>
        <p className="subtle-footnote"><Icon name="monitor" size={14} />Manual, local folder backups only in this release.</p>
      </aside>
    </div>
  </>
}

function RestorePage({ model, selectedId, onSelect, navigate, confirm }: {
  model: QuickSave; selectedId: string | null; onSelect: (id: string) => void;
  navigate: (page: Page) => void; confirm: (kind: Confirmation) => void
}) {
  const selected = model.snapshots.find((snapshot) => snapshot.id === selectedId)
  const disabled = !model.native || model.working
  return <>
    <div className="page-intro"><span className="eyebrow">A version worth returning to</span><h2>Bring your files back.</h2>
      <p>Choose a saved snapshot and an empty destination. Your existing files stay right where they are.</p></div>
    <div className="restore-safety"><span className="icon-tile"><Icon name="shield" size={20} /></span>
      <div><strong>A fresh folder. No overwrites.</strong><p>The native engine rejects nonempty destinations. In-place rollback is not supported.</p></div>
      <span className="badge badge-green">Empty-folder restore</span>
    </div>
    <div className="restore-grid">
      <section className="card snapshot-browser">
        <div className="card-heading"><div><span className="eyebrow">01 / Choose a version</span><h3>Snapshot history</h3></div>
          <Button variant="ghost" icon="refresh" disabled={disabled || !model.canRead || !model.pathsReady || model.mode !== 'existing'}
            onClick={() => { void model.loadSnapshots() }}>Refresh</Button></div>
        <SnapshotBrowser model={model} selectedId={selectedId} onSelect={onSelect} onConnect={() => navigate('backups')} />
      </section>
      <aside className="card restore-destination">
        <div className="card-heading"><div><span className="eyebrow">02 / Choose a destination</span><h3>A place to restore</h3></div></div>
        <div className="destination-body">
          <div className="selected-snapshot">
            <span className="small-label">Selected snapshot</span>
            <strong>{selected ? date(selected.createdAt) : 'No snapshot selected'}</strong>
            {selected ? <><code title={selected.id}>{selected.id}</code>
              <span>{number(selected.totalFiles)} files · {bytes(selected.logicalBytes)} logical data</span></>
              : <p>Choose a version from your history.</p>}
          </div>
          <PathField label="Empty destination folder" value={model.workspace.destination} icon="folder"
            placeholder="Choose an existing empty folder" hint="The backend verifies the destination before writing. Source and repository overlap is not permitted."
            onChoose={() => { void model.pick('destination') }} disabled={disabled} />
          <Button icon="restore" className="full-width" disabled={disabled || !model.canWrite || !model.verified || !selected || !model.workspace.destination || !model.snapshotsLoaded}
            onClick={() => confirm('restore')}>Restore selected snapshot</Button>
          <div className="destination-repository"><Icon name="drive" size={16} /><div>
            <span>From your local repository</span><strong title={model.workspace.repository}>
              {model.workspace.repository ? folderName(model.workspace.repository) : 'No repository open'}</strong>
          </div></div>
          <button type="button" className="text-button" onClick={() => navigate('backups')}>Change repository<Icon name="arrow" size={14} /></button>
        </div>
      </aside>
    </div>
    <div className="quiet-inline"><Icon name="info" size={16} /><p>Review the exact paths in the native confirmation before restoring. You can cancel there; once a native job starts, cancellation is not available. Keep QuickSave open until its final result.</p></div>
  </>
}

function flattenReport(report: NativeReport): { key: string; value: string; flag: boolean | null }[] {
  const rows: { key: string; value: string; flag: boolean | null }[] = []
  function visit(node: NativeReport, prefix = '', depth = 0) {
    for (const [key, value] of Object.entries(node).slice(0, 40)) {
      if (rows.length >= 80) break
      const label = `${prefix}${key}`.slice(0, 200)
      // Capability reports are metadata, not a key-export surface.
      if (/secret|key_bytes|master_key|token|password/i.test(key)) {
        rows.push({ key: label, value: 'Sensitive field not displayed', flag: null })
        continue
      }
      const nested = record(value)
      if (nested && depth < 3) {
        visit(nested, `${label}.`, depth + 1)
        continue
      }
      rows.push({
        key: label,
        value: typeof value === 'boolean' ? (value ? 'Yes' : 'No')
          : typeof value === 'string' ? value.slice(0, 2_000)
            : typeof value === 'number' ? String(value)
              : value === null ? 'Not reported'
                : Array.isArray(value) ? value.slice(0, 16).map((part) => typeof part === 'string' || typeof part === 'number' ? String(part).slice(0, 200) : '[structured value]').join(', ')
                  : '[structured value]',
        flag: typeof value === 'boolean' ? value : null,
      })
    }
  }
  visit(report)
  return rows
}

function ReportView({ report }: { report: NativeReport }) {
  const entries = flattenReport(report)
  return entries.length > 0 ? <dl className="technical-report">{entries.map((entry) => <div key={entry.key}>
    <dt>{entry.key}</dt><dd>{entry.flag !== null
      ? <span className={`badge ${entry.flag ? 'badge-green' : 'badge-neutral'}`}>{entry.value}</span>
      : entry.value}</dd>
  </div>)}</dl> : <p className="report-placeholder">The backend returned an empty report.</p>
}

function CapabilitiesPage({ model }: { model: QuickSave }) {
  const baseline: { icon: IconName; title: string; description: string }[] = [
    { icon: 'folder', title: 'Local folder backups', description: 'Manually capture a folder into a separate local QuickSave repository.' },
    { icon: 'lock', title: 'Encrypted repository', description: 'The native engine reads your external recovery-key file. The interface receives its path only.' },
    { icon: 'restore', title: 'Additive version history', description: 'New snapshots preserve previous versions. There is no automatic retention or deletion.' },
    { icon: 'shield', title: 'Empty-folder restore', description: 'Restore into an approved empty destination. Existing files are not replaced.' },
  ]
  return <>
    <div className="page-intro"><span className="eyebrow">Built with clear boundaries</span><h2>Know what’s keeping your files.</h2>
      <p>Real capabilities, explicit limits. No promises hidden behind a green checkmark.</p></div>
    <section className="release-banner"><span className="release-symbol"><Icon name="sprout" size={27} /></span>
      <div><span className="eyebrow">The local-first foundation</span><h3>Pre-release. Intentionally focused.</h3>
        <p>QuickSave is a standalone app, separate from No Land. This release implements local folder backups—not application profiles, cloud backup, or an app-consistent snapshot service.</p></div>
      <span className="badge badge-neutral">v0.1.0</span>
    </section>
    <div className="section-heading"><h3>Local engine scope</h3><span>Implemented workflow · native checks still apply</span></div>
    <section className="capability-grid" aria-label="Local engine capabilities">
      {baseline.map((item) => <article className="card capability-card" key={item.title}>
        <span className="icon-tile"><Icon name={item.icon} size={21} /></span>
        <h3>{item.title}</h3><p>{item.description}</p><span className="capability-label">Local engine</span>
      </article>)}
    </section>
    <div className="capability-details-grid">
      <section className="card">
        <div className="card-heading"><div><span className="eyebrow">From this native runtime</span><h3>Platform capability report</h3></div>
          <span className={`badge ${model.report ? 'badge-green' : 'badge-neutral'}`}>{model.checking ? 'Checking' : model.report ? 'Reported' : 'Unavailable'}</span></div>
        {model.report ? <ReportView report={model.report} /> : <p className="report-placeholder">
          {model.checking ? 'Waiting for the native backend…' : model.reportError || 'Launch the desktop application to read the native platform report. Browser preview cannot validate filesystem safety.'}
        </p>}
        <div className="card-bottom-note"><Icon name="info" size={15} />Windows, macOS, and Linux acceptance must be tested separately. A build on one platform is not proof of support on another.</div>
      </section>
      <section className="card limits-card">
        <div className="card-heading"><div><span className="eyebrow">Not available in this release</span><h3>No pretend switches.</h3></div></div>
        <ul className="limits-list">
          <li><Icon name="cloud" size={20} /><div><strong>Cloud providers & remote machines</strong><span>Not implemented. Local repositories only.</span></div><span className="badge badge-neutral">Planned</span></li>
          <li><Icon name="clock" size={20} /><div><strong>Automatic scheduling</strong><span>Start backups manually in this app.</span></div><span className="badge badge-neutral">Planned</span></li>
          <li><Icon name="monitor" size={20} /><div><strong>Application profiles & atomic capture</strong><span>Stable-file capture is not application-wide consistency.</span></div><span className="badge badge-neutral">Not available</span></li>
          <li><Icon name="key" size={20} /><div><strong>Native key vault & key recovery</strong><span>An external recovery-key file is required.</span></div><span className="badge badge-neutral">Not available</span></li>
          <li><Icon name="restore" size={20} /><div><strong>Overwrite restore & deletion</strong><span>No in-place rollback or history retirement.</span></div><span className="badge badge-neutral">Not available</span></li>
        </ul>
      </section>
    </div>
    <details className="card directories-details">
      <summary><span><Icon name="folder" size={18} />Native application directories</span><Icon name="chevron" size={17} /></summary>
      {model.directories ? <ReportView report={model.directories} /> : <p className="report-placeholder">{model.directoriesError || 'No native directories report is available in this session.'}</p>}
    </details>
  </>
}

function ConfirmationDialog({ kind, model, selected, onCancel, onConfirm }: {
  kind: Exclude<Confirmation, null>; model: QuickSave; selected: Snapshot | undefined;
  onCancel: () => void; onConfirm: () => void
}) {
  const titleId = useId()
  const descriptionId = useId()
  const container = useRef<HTMLDivElement>(null)
  const cancelButton = useRef<HTMLButtonElement>(null)
  useEffect(() => {
    const previous = document.activeElement
    const overflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    cancelButton.current?.focus()
    return () => {
      document.body.style.overflow = overflow
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus()
    }
  }, [])
  const initializing = kind === 'initialize'
  const restoring = kind === 'restore'
  const title = initializing ? 'Create this local repository?' : restoring ? 'Restore this snapshot?' : 'Save a snapshot of this folder?'
  return createPortal(<div className="modal-backdrop" onMouseDown={(event) => {
    if (event.target === event.currentTarget) onCancel()
  }}>
    <div className="confirmation-dialog" role="dialog" aria-modal="true" aria-labelledby={titleId}
      aria-describedby={`${descriptionId} ${descriptionId}-approval`} ref={container} onKeyDown={(event) => {
        if (event.key === 'Escape') { event.stopPropagation(); onCancel() }
        if (event.key === 'Tab') {
          const focusable = container.current?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)')
          if (!focusable?.length) return
          const first = focusable[0]
          const last = focusable[focusable.length - 1]
          if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
          else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
        }
      }}>
      <button type="button" className="modal-close icon-button" onClick={onCancel} aria-label="Close confirmation"><Icon name="close" size={20} /></button>
      <span className="modal-symbol"><Icon name={initializing ? 'key' : restoring ? 'restore' : 'backup'} size={28} /></span>
      <span className="eyebrow">One last look</span><h2 id={titleId}>{title}</h2>
      <p id={descriptionId}>{initializing
        ? 'The native engine will initialize the selected empty folder and create a new external recovery-key file. It must not replace an existing key.'
        : restoring ? 'The native engine will restore into the selected empty folder. Nonempty destinations are rejected; no existing files may be overwritten.'
          : 'The native engine will validate and capture your source as a new encrypted snapshot. Your existing snapshot history is kept.'}</p>
      <p id={`${descriptionId}-approval`}>Next, approve these exact paths in QuickSave’s separate native confirmation. This preview grants no filesystem access. Cancelling native approval prevents the operation.</p>
      <dl className="confirmation-paths">
        <div><dt>Repository</dt><dd>{model.workspace.repository}</dd></div>
        {!initializing && <div><dt>{restoring ? 'Snapshot' : 'Source'}</dt><dd>{restoring ? selected?.id : model.workspace.source}</dd></div>}
        {restoring && <div><dt>Destination</dt><dd>{model.workspace.destination}</dd></div>}
        <div><dt>{initializing ? 'New key file' : 'Key file'}</dt><dd>{model.workspace.keyFile}</dd></div>
      </dl>
      <div className="modal-warning"><Icon name="info" size={18} /><p>{initializing
        ? 'Keep the key outside the repository and source. Store a separate secure copy: there is no password reset or replacement key.'
        : restoring ? 'Keep QuickSave open until a final native status is reported. Once the job starts, cancellation and in-place rollback are not available.'
          : 'Pause apps writing to the source. This is stable-file capture, not an application-wide atomic snapshot. Once the job starts, there is no cancellation control.'}</p></div>
      <div className="modal-actions"><button type="button" className="button button-secondary" ref={cancelButton} onClick={onCancel}>Cancel</button>
        <Button icon={initializing ? 'plus' : restoring ? 'restore' : 'backup'} onClick={onConfirm}>
          {initializing ? 'Create repository & key' : restoring ? 'Restore to empty folder' : 'Start backup'}
        </Button></div>
    </div>
  </div>, document.body)
}

export default function App() {
  const model = useQuickSave()
  const [page, setPage] = useState<Page>('overview')
  const [confirmation, setConfirmation] = useState<Confirmation>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const main = useRef<HTMLElement>(null)
  const currentPage = pages.find((entry) => entry.id === page)!
  const selected = model.snapshots.find((snapshot) => snapshot.id === selectedId)

  function navigate(next: Page) {
    setPage(next)
    main.current?.scrollIntoView?.({ block: 'start' })
  }
  function selectRestore(id: string) {
    setSelectedId(id)
    navigate('restore')
  }
  function confirmOperation() {
    const kind = confirmation
    setConfirmation(null)
    if (kind === 'initialize') void model.initialize()
    if (kind === 'backup') void model.backup()
    if (kind === 'restore' && selected && model.snapshotsLoaded) void model.restore(selected.id)
  }
  return <div className="app-shell">
    <a className="skip-link" href="#main-content">Skip to content</a>
    <aside className="sidebar">
      <Brand />
      <div className="sidebar-section-label">Your workspace</div>
      <nav className="main-nav" aria-label="Main navigation">
        {pages.map((entry) => <button key={entry.id} type="button" onClick={() => navigate(entry.id)}
          className={page === entry.id ? 'active' : ''} aria-current={page === entry.id ? 'page' : undefined}>
          <Icon name={entry.icon} size={20} /><span>{entry.label}</span>{page === entry.id && <span className="nav-indicator" />}
        </button>)}
      </nav>
      <div className="sidebar-bottom">
        <div className="local-promise"><Icon name="sprout" size={26} /><h3>A little less worry.</h3>
          <p>A local home for the files<br />you don’t want to lose.</p></div>
        <div className="sidebar-machine"><span className="machine-icon"><Icon name="monitor" size={19} /></span>
          <div><strong>This computer</strong><span>Local-only workspace</span></div><Icon name="lock" size={14} /></div>
        <div className="sidebar-version"><span>QuickSave 0.1.0</span><span>PRE-RELEASE</span></div>
      </div>
    </aside>
    <main className="main-shell" id="main-content" tabIndex={-1} ref={main}>
      <header className="topbar"><div className="breadcrumb"><span>Workspace</span><Icon name="chevron" size={13} /><strong>{currentPage.label}</strong></div>
        <div className="runtime-pill"><span className={`status-dot ${model.report ? 'status-ready' : ''}`} />
          {model.checking ? 'Checking native backend' : model.report ? 'Native backend connected' : model.native ? 'Capability report unavailable' : 'Browser preview'}</div>
      </header>
      <div className="page-content">
        <div className="page-heading"><h1>{currentPage.label}</h1><span><Icon name="monitor" size={14} />Local workspace</span></div>
        {!model.native && <div className="runtime-banner" role="status"><Icon name="info" size={19} /><div><strong>Preview only. Your files are not being backed up.</strong>
          <span>Native folder pickers and backup commands require the QuickSave desktop application. No demo data or browser fallback is used.</span></div></div>}
        {model.reportError && <div className="runtime-banner warning-banner" role="alert"><Icon name="warning" size={19} /><div>
          <strong>The native capability check did not finish successfully.</strong><span>{model.reportError}</span></div></div>}
        {model.native && !model.checking && (model.historyError || (model.report && !model.canWrite)) && !model.untrackedError && <div className="runtime-banner warning-banner" role="alert">
          <Icon name="warning" size={19} /><div><strong>Repository creation, backup, and restore are currently disabled.</strong>
            <span>{model.unavailableReason}{model.historyError ? ` ${model.historyError}` : ''}</span>
            <Button variant="ghost" icon="refresh" onClick={model.retryChecks} disabled={model.working}>Retry native checks</Button>
          </div></div>}
        {model.untrackedError && <div className="runtime-banner warning-banner" role="alert"><Icon name="warning" size={19} />
          <div><strong>A native operation may be active. New operations are blocked.</strong><span>{model.untrackedError}</span>
            <Button variant="secondary" icon="refresh" onClick={model.retryChecks} disabled={model.checking}>Recover native status</Button>
          </div></div>}
        {model.notice && <div className={`notice notice-${model.notice.tone}`} role={model.notice.tone === 'error' ? 'alert' : 'status'}>
          <Icon name={model.notice.tone === 'error' ? 'warning' : model.notice.tone === 'success' ? 'check' : 'info'} size={19} />
          <div><strong>{model.notice.title}</strong><p>{model.notice.message}</p></div>
          <button className="icon-button" type="button" aria-label="Dismiss message" onClick={model.dismissNotice}><Icon name="close" size={17} /></button>
        </div>}
        <OperationPanel model={model} />
        {page === 'overview' && <Overview model={model} navigate={navigate} onRestore={selectRestore} />}
        {page === 'backups' && <BackupPage model={model} confirm={setConfirmation} navigate={navigate} />}
        {page === 'restore' && <RestorePage model={model} selectedId={selected?.id ?? null}
          onSelect={setSelectedId} navigate={navigate} confirm={setConfirmation} />}
        {page === 'capabilities' && <CapabilitiesPage model={model} />}
        <footer className="page-footer"><span><Icon name="lock" size={12} />Local by design. Yours to keep.</span>
          <span>Pre-release · Manual folder backups</span></footer>
      </div>
    </main>
    {confirmation && <ConfirmationDialog kind={confirmation} model={model} selected={selected}
      onCancel={() => setConfirmation(null)} onConfirm={confirmOperation} />}
  </div>
}
