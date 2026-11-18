// SPDX-License-Identifier: GPL-3.0-only
import { useEffect, useRef, useState } from 'react'
import {
  api, chooseFiles, chooseFolder, MAX_APP_SELECTION, normalizeDeletePreview, normalizeRestorePreview, safeError, terminal,
  type Activity, type Bundle, type CatalogPage, type DeletePreview, type Provider, type RestoreMode,
  type RestorePlan, type RestorePreview, type Software,
} from './api'
import { bytes, date, number } from './format'
import { FileBrowser } from './FileBrowser'
import { BatchActivityList, UploadBatchControls } from './BatchUpload'
import { backupScope, BundleCoverageNote, BundleIdentities, CatalogFreshnessNote, PendingDeletions } from './CatalogDetails'
import { Icon, type IconName } from './Icon'
import { ProviderDialog } from './ProviderDialog'
import { Button, Dialog, InlineError } from './ui'
import { useQuickSave, type QuickSave } from './useQuickSave'

type Page = 'overview' | 'backup' | 'restore'
const pages: { id: Page; label: string; icon: IconName }[] = [
  { id: 'overview', label: 'Overview', icon: 'overview' },
  { id: 'backup', label: 'Backup', icon: 'backup' },
  { id: 'restore', label: 'Restore', icon: 'restore' },
]
const softwareStatus: Record<Software['status'], string> = {
  needs_backup: 'Needs backup', saved: 'Saved', checking: 'Checking',
  uploading: 'Uploading', error: 'Error', not_tracked: 'Not tracked',
}
const PAGE_SIZE = 20
const connected = (model: QuickSave) => model.dashboard?.providers.filter((provider) => provider.status === 'connected') ?? []
const canUse = (model: QuickSave) => model.ready && !model.busy
const trackedSoftware = (model: QuickSave) => model.dashboard?.software.filter((item) => item.tracked && item.status !== 'not_tracked') ?? []
const restoreModes: Record<RestoreMode, string> = { create_new: 'Create new', merge: 'Merge', replace: 'Replace' }

function Brand() {
  return <div className="brand" aria-label="QuickSave">
    <span className="brand-mark" aria-hidden="true">
      <svg width="27" height="28" viewBox="0 0 27 28" fill="none">
        <path d="M5 3h7v7H5V3Zm10 0h7v7h-7V3ZM5 13h7v7H5v-7Z" fill="currentColor" />
        <path d="m15 13 9 9-5 5-9-9 5-5Z" fill="currentColor" />
      </svg>
    </span><span>QuickSave<span className="brand-period">.</span></span>
  </div>
}

function Overview({ model, onConnect, navigate }: {
  model: QuickSave; onConnect: () => void; navigate: (page: Page) => void
}) {
  const summary = model.dashboard?.summary
  const needing = trackedSoftware(model).filter((software) => software.status === 'needs_backup')
  return <div className="page-stack">
    <section className="card backup-summary">
      <div><span className="muted">Needs backup</span>
        <strong className="summary-count">{summary ? number(summary.needsBackup) : '—'}</strong>
      </div>
      <Button icon="backup" variant="secondary" onClick={() => navigate('backup')}>View software</Button>
    </section>
    {needing.length > 0 && <ul className="overview-software card">{needing.slice(0, 5).map((software) => <li key={software.id}>
      <Icon name="monitor" size={20} /><strong className="truncate" title={software.name}>{software.name}</strong>
      <span className="status-label">Needs backup</span>
    </li>)}</ul>}
    <section className="card overview-providers">
      <div><h2>Cloud providers</h2>
        <p className="muted">{summary ? `${number(summary.connectedProviders)} connected` : 'No connections loaded'}</p>
      </div>
      <Button icon="plus" variant="secondary" disabled={!canUse(model)} onClick={onConnect}>Connect providers</Button>
    </section>
    {(!model.tracking?.enabled || model.tracking.scanning || model.trackingError) && <TrackingPanel model={model} />}
  </div>
}

function ActivityRow({ item, model }: { item: Activity; model: QuickSave }) {
  const metric = item.completedBytes !== undefined
    ? `${bytes(item.completedBytes)}${item.totalBytes !== undefined ? ` / ${bytes(item.totalBytes)}` : ''}`
    : item.completedFiles !== undefined
      ? `${number(item.completedFiles)}${item.totalFiles !== undefined ? ` / ${number(item.totalFiles)}` : ''} files`
      : null
  const hasProgress = !terminal(item.state) && item.totalBytes !== undefined && item.totalBytes > 0
    && item.completedBytes !== undefined && item.completedBytes <= item.totalBytes
  return <li className={`activity-row activity-${item.state}`}>
    <details>
      <summary>
        <Icon name={item.kind === 'download' ? 'download' : item.kind === 'delete' ? 'trash'
          : item.kind === 'connect' ? 'cloud' : 'backup'} size={18} />
        <strong className="truncate" title={item.name}>{item.name}</strong>
        <span className="activity-state">{item.state}</span>
        {metric && <span className="activity-metric">{metric}</span>}
        <Icon name="chevron" size={15} />
      </summary>
      {hasProgress && <progress aria-label={`${item.name} bytes`} max={item.totalBytes} value={item.completedBytes} />}
      <div className="activity-details">
        <dl>
          <div><dt>Action</dt><dd>{item.kind}</dd></div>
          {item.phase && <div><dt>Phase</dt><dd>{item.phase}</dd></div>}
          {item.startedAt && <div><dt>Started</dt><dd>{date(item.startedAt)}</dd></div>}
          {item.completedFiles !== undefined && <div><dt>Files</dt>
            <dd>{number(item.completedFiles)}{item.totalFiles !== undefined ? ` / ${number(item.totalFiles)}` : ''}</dd></div>}
          <div><dt>Operation</dt><dd className="truncate" title={item.id}>{item.id}</dd></div>
        </dl>
        {item.error && <p className="error-text">{item.error}</p>}
        <div className="row-actions">
          {item.canCancel && !terminal(item.state) && <Button variant="secondary" disabled={!canUse(model)}
            onClick={() => { void model.run('cancel', { operationId: item.id }) }}>Cancel operation</Button>}
          {item.canRetry && terminal(item.state) && <Button variant="secondary" disabled={!canUse(model)}
            onClick={() => { void model.run('retry', { operationId: item.id }) }}>Retry original operation</Button>}
          {item.kind === 'download' && item.canRecover && (item.state === 'failed' || item.state === 'interrupted')
            && <Button variant="secondary" disabled={!canUse(model)}
              onClick={() => { void model.run('recover_restore', { operationId: item.id }) }}>Recover original restore</Button>}
        </div>
      </div>
    </details>
  </li>
}

function ActivityList({ model }: { model: QuickSave }) {
  const [showAll, setShowAll] = useState(false)
  const ordered = model.activity.filter((item) => !item.planSetId && !model.batches.some((batch) => batch.operationId === item.id))
    .sort((a, b) => Number(terminal(a.state)) - Number(terminal(b.state)))
  if (!ordered.length && !model.pollIssue) return null
  return <section className="activity-section" aria-label="Activity">
    <div className="section-heading"><h2>Activity</h2>
      {ordered.length > 3 && <button className="text-button" type="button" onClick={() => setShowAll(!showAll)}>
        {showAll ? 'Show less' : `Show all (${ordered.length})`}</button>}
    </div>
    {model.pollIssue && <InlineError message={model.pollIssue} onRetry={model.resumePolling} />}
    <ul className="activity-list card">{ordered.slice(0, showAll ? 128 : 3).map((item) => <ActivityRow key={item.id} item={item} model={model} />)}</ul>
  </section>
}

function TrackingPanel({ model }: { model: QuickSave }) {
  const tracking = model.tracking
  const defaultProviderId = connected(model).find((provider) => !provider.readOnly)?.id
  return <section className="card tracking-panel" aria-label="App tracking">
    <div className="section-heading">
      <div className="min-width-zero"><h2>App tracking</h2>
        <p className="muted">{!model.native ? 'Native approval is required to track apps.'
          : !tracking ? 'App-tracking status is unavailable.'
            : !tracking.enabled ? 'Enable automatic local app inventory with native approval.'
              : tracking.scanning ? `Checking apps: ${number(tracking.completedApps)} / ${number(tracking.totalApps)}`
                : 'App tracking enabled. Local files stay on this device.'}</p>
      </div>
      {tracking?.enabled
        ? <Button variant="secondary" icon="refresh" disabled={!canUse(model) || tracking.scanning}
          onClick={() => { void model.run('refresh_app_tracking', {}) }}>Refresh app tracking</Button>
        : <Button icon="monitor" disabled={!canUse(model) || !tracking}
          onClick={() => { void model.run('enable_app_tracking', {
            enabled: true, ...(defaultProviderId ? { defaultProviderId } : {}),
            roles: ['installation', 'save', 'config', 'runtime'],
          }) }}>Enable app tracking</Button>}
    </div>
    {tracking?.scanning && tracking.totalApps > 0 && <progress aria-label="Apps checked"
      max={tracking.totalApps} value={tracking.completedApps} />}
    {model.trackingError && <InlineError message={model.trackingError} onRetry={() => { void model.refreshTracking() }} />}
    {model.trackingPollIssue && <InlineError message={model.trackingPollIssue} onRetry={model.resumeTrackingPolling} />}
    {!!tracking?.diagnostics.length && <details className="dependency-list">
      <summary>Discovery diagnostics ({number(tracking.diagnostics.length)})</summary>
      <ul>{tracking.diagnostics.map((diagnostic, index) => <li key={index}>
        {(diagnostic.name || diagnostic.appId) && <strong className="truncate" title={diagnostic.name ?? diagnostic.appId}>
          {diagnostic.name ?? diagnostic.appId}</strong>}
        <p className="muted">{diagnostic.message}</p>
        {diagnostic.path && <span className="truncate muted" title={diagnostic.path}>{diagnostic.path}</span>}
      </li>)}</ul>
    </details>}
  </section>
}

function SoftwareRow({ software, model, expanded, onExpand, selected, selectionFull, onSelect }: {
  software: Software; model: QuickSave; expanded: boolean; onExpand: () => void
  selected: boolean; selectionFull: boolean; onSelect: (checked: boolean) => void
}) {
  const providers = connected(model)
  const provider = providers.find((item) => item.id === software.providerId)
  const inProgress = model.activity.some((item) => item.softwareId === software.id && !terminal(item.state))
  const disabled = !canUse(model) || inProgress || software.status === 'uploading'
  const writable = provider && !provider.readOnly
  async function upload(fileIds?: string[]) {
    if (!provider || !software.tracked || provider.readOnly) return
    await model.run('upload', { softwareId: software.id, providerId: provider.id, ...(fileIds ? { fileIds } : {}) })
  }
  return <li className="software-item">
    <div className="software-row">
      <div className="software-title">
        <input type="checkbox" aria-label={`Include app ${software.name} in batch`} checked={selected}
          disabled={!canUse(model) || !software.tracked || (selectionFull && !selected)}
          onChange={(event) => onSelect(event.target.checked)} />
        <button className="software-name" type="button" aria-expanded={expanded} onClick={onExpand}
        aria-label={`${expanded ? 'Hide' : 'Browse'} files for ${software.name}`} disabled={!software.tracked || !model.ready}>
        <Icon name="chevron" size={16} /><Icon name="monitor" size={20} />
        <strong className="truncate" title={software.name}>{software.name}</strong>
        </button>
      </div>
      <span className={`status-label status-${software.status}`} title={software.error || undefined}>
        {softwareStatus[software.status]}
      </span>
      <label className="provider-select"><span className="sr-only">Provider for {software.name}</span>
        <select value={software.providerId ?? ''} disabled={disabled || !software.tracked || !providers.length}
          onChange={(event) => {
            if (event.target.value) void model.run('set_provider', { softwareId: software.id, providerId: event.target.value })
          }}>
          <option value="" disabled>Choose provider</option>
          {software.providerId && !provider && <option value={software.providerId} disabled>Unavailable provider</option>}
          {providers.map((item) => <option key={item.id} value={item.id}>{item.name}{item.readOnly ? ' (read-only)' : ''}</option>)}
        </select>
      </label>
      <label className="autosave-control">
        <input type="checkbox" role="switch" aria-label={`Autosave for ${software.name}`}
          checked={software.autosave} disabled={disabled || !software.tracked || !writable}
          onChange={(event) => {
            if (provider) void model.run('set_autosave', {
              softwareId: software.id, providerId: provider.id, enabled: event.target.checked,
            })
          }} /><span className="mobile-label">Autosave</span>
      </label>
      <Button variant="secondary" icon="backup" disabled={disabled || !writable}
        onClick={() => { void upload() }}>Upload</Button>
    </div>
    {software.error && <p className="software-error error-text">{software.error}</p>}
    {expanded && software.tracked && <>
      <section className="local-inventory" aria-label={`Local inventory for ${software.name}`}>
        <p className="muted">{number(software.fileCount ?? null)} files · {bytes(software.logicalBytes ?? null)}</p>
        {!!software.roots?.length && <ul className="root-list">{software.roots.map((root) => <li key={root.id}>
          <span className="truncate" title={root.path}>{root.path}</span>
          {(root.roles?.length || root.role) && <span className="muted">{root.roles?.join(', ') || root.role}</span>}
          {root.fileCount !== undefined && <span className="muted">{number(root.fileCount)} files</span>}
        </li>)}</ul>}
      </section>
      <FileBrowser key={software.id} label={`Files for ${software.name}`}
        load={(cursor) => api.softwareFiles(software.id, cursor)} disabled={disabled || !writable}
        roots={software.roots} transferLabel="Upload" onTransfer={upload} />
    </>}
  </li>
}

function BackupPage({ model }: { model: QuickSave }) {
  const [expanded, setExpanded] = useState<string | null>(null)
  const [page, setPage] = useState(0)
  const [filter, setFilter] = useState('')
  const [selected, setSelected] = useState<Map<string, string>>(new Map())
  const software = trackedSoftware(model)
  const matches = software.filter((item) => item.name.toLocaleLowerCase().includes(filter.toLocaleLowerCase()))
  const visiblePage = Math.min(page, Math.max(0, Math.ceil(matches.length / PAGE_SIZE) - 1))
  const defaultProvider = connected(model).find((provider) => !provider.readOnly)?.id
  const selectedApps = [...selected].map(([id, name]) => ({ id, name }))
  function select(item: Software, checked: boolean) {
    setSelected((previous) => {
      const next = new Map(previous)
      if (checked && next.size < MAX_APP_SELECTION) next.set(item.id, item.name)
      else if (!checked) next.delete(item.id)
      return next
    })
  }
  async function addFiles() {
    const paths = await model.pick(chooseFiles)
    if (paths?.length) await model.run('add_files', { paths, ...(defaultProvider ? { providerId: defaultProvider } : {}) })
  }
  return <div className="page-stack">
    <div className="section-heading backup-heading"><p className="muted">Keep local files; upload changes in background.</p>
      <div className="row-actions">
        <Button variant="secondary" icon="file" disabled={!canUse(model)} onClick={() => { void addFiles() }}>Add files</Button>
      </div>
    </div>
    <TrackingPanel model={model} />
    <UploadBatchControls model={model} selected={selectedApps}
      onClear={() => setSelected(new Map())} onUploaded={() => setSelected(new Map())} />
    {selected.size >= MAX_APP_SELECTION && <p className="muted">512-app selection limit. “Preview upload all” freezes the entire native-approved inventory separately.</p>}
    {software.length > PAGE_SIZE && <label className="field search-field">Find software
      <input type="search" value={filter} maxLength={200} onChange={(event) => { setFilter(event.target.value); setPage(0); setExpanded(null) }} />
    </label>}
    <section className="card software-list" aria-label="Software">
      <div className="software-columns" aria-hidden="true"><span>Name</span><span>Status</span>
        <span>Provider</span><span>Autosave</span><span /></div>
      {matches.length ? <ul>{matches.slice(visiblePage * PAGE_SIZE, (visiblePage + 1) * PAGE_SIZE).map((item) => <SoftwareRow
        key={item.id} software={item} model={model} expanded={expanded === item.id}
        selected={selected.has(item.id)} selectionFull={selected.size >= MAX_APP_SELECTION}
        onSelect={(checked) => select(item, checked)}
        onExpand={() => setExpanded(expanded === item.id ? null : item.id)} />)}</ul>
        : <p className="empty-line">{model.loading ? 'Loading local inventory…' : filter ? 'No matching software.'
          : model.tracking?.scanning ? 'Native app inventory is in progress. Only indexed local bundles appear here.'
            : 'No tracked local bundles reported.'}</p>}
      {matches.length > PAGE_SIZE && <div className="pagination">
        <span className="muted">{number(matches.length)} software · Page {visiblePage + 1}</span>
        <Button variant="ghost" disabled={visiblePage === 0}
          onClick={() => { setPage(visiblePage - 1); setExpanded(null) }}>Previous</Button>
        <Button variant="ghost" disabled={(visiblePage + 1) * PAGE_SIZE >= matches.length}
          onClick={() => { setPage(visiblePage + 1); setExpanded(null) }}>Next</Button>
      </div>}
    </section>
  </div>
}

function DeleteDialog({ preview, bundle, model, onClose, onDeleted }: {
  preview: DeletePreview; bundle: Bundle; model: QuickSave; onClose: () => void; onDeleted: () => void
}) {
  const [acknowledged, setAcknowledged] = useState(false)
  const [consumed, setConsumed] = useState(false)
  async function confirmDelete() {
    if (consumed || (preview.requiresDependencyAcknowledgement && !acknowledged)) return
    setConsumed(true)
    const result = await model.run('delete_cloud', {
      providerId: bundle.providerId, previewId: preview.previewId, acknowledgeDependencies: acknowledged,
    })
    if (result !== undefined) { onClose(); onDeleted() }
  }
  return <Dialog title="Delete cloud backup" onClose={onClose} busy={!!model.busy}>
    <p className="dialog-note">Delete this frozen preview only. Local files are kept.</p>
    <div className="delete-summary"><strong className="truncate" title={bundle.name}>{bundle.name}</strong>
      <span>{number(preview.items)} items · {bytes(preview.bytes)} logical data</span></div>
    {preview.physicalBytes !== undefined && <p className="preview-metric muted">{bytes(preview.physicalBytes)} physical data
      {preview.packCount !== undefined ? ` · ${number(preview.packCount)} packs` : ''}</p>}
    {preview.dependentBundles.length > 0 && <details className="dependency-list"><summary>Affected dependent backups ({preview.dependentBundleCount})</summary>
      <ul>{preview.dependentBundles.map((dependency) => <li className="truncate" title={dependency.name ?? dependency.id}
        key={dependency.id}>{dependency.name ?? dependency.id}</li>)}</ul>
    </details>}
    {preview.requiresDependencyAcknowledgement && <label className="acknowledgement">
      <input type="checkbox" checked={acknowledged} disabled={consumed || !!model.busy}
        onChange={(event) => setAcknowledged(event.target.checked)} />
      <span>I acknowledge that {number(preview.dependentBundleCount)} dependent backups in this preview are affected.</span>
    </label>}
    {consumed && !model.busy && <p className="error-text">This preview has been submitted. Close and request a fresh preview before trying again.</p>}
    <div className="modal-actions"><Button variant="secondary" disabled={!!model.busy} onClick={onClose}>Cancel</Button>
      <Button variant="danger" icon="trash" disabled={!canUse(model) || consumed || (preview.requiresDependencyAcknowledgement && !acknowledged)}
        onClick={() => { void confirmDelete() }}>Delete with native confirmation</Button></div>
  </Dialog>
}

function RestoreDialog({ preview, plan, bundle, model, onClose }: {
  preview: RestorePreview; plan: RestorePlan; bundle: Bundle; model: QuickSave; onClose: () => void
}) {
  const [acknowledged, setAcknowledged] = useState(false)
  const [consumed, setConsumed] = useState(false)
  async function confirmRestore() {
    if (consumed || (preview.requiresOverwriteAcknowledgement && !acknowledged)) return
    setConsumed(true)
    const result = await model.run('download', {
      restorePreviewId: preview.previewId, overwriteAcknowledgement: acknowledged,
    })
    if (result !== undefined) onClose()
  }
  return <Dialog title="Review restore" onClose={onClose} busy={!!model.busy}>
    <p className="dialog-note">Restore only the native-validated frozen plan below.</p>
    <div className="delete-summary">
      <strong className="truncate" title={bundle.name}>{bundle.name}</strong>
      <span>{number(preview.files)} files · {bytes(preview.bytes)}</span>
      <span>{restoreModes[plan.mode]}</span>
      <span className="truncate" title={plan.destination}>{plan.destination}</span>
    </div>
    <BundleCoverageNote bundle={bundle} />
    {preview.summary && <p className="preview-metric muted">{preview.summary}</p>}
    {(preview.conflicts.length > 0 || (preview.conflictCount ?? 0) > 0) && <details className="dependency-list">
      <summary>Conflicts ({number(preview.conflictCount ?? preview.conflicts.length)})</summary>
      {preview.conflictCount !== undefined && preview.conflictCount > preview.conflicts.length && <p className="muted">
        Showing {number(preview.conflicts.length)} of {number(preview.conflictCount)} native conflicts. The frozen plan retains the complete inventory.</p>}
      <ul>{preview.conflicts.map((conflict, index) => <li key={index}>
        <span className="truncate" title={conflict.path}>{conflict.path}</span>
        {conflict.reason && <p className="muted">{conflict.reason}</p>}
      </li>)}</ul>
    </details>}
    {(preview.blockingConflicts ?? 0) > 0 && <p className="error-text">
      {number(preview.blockingConflicts!)} blocking conflicts remain in the native plan. An acknowledgement cannot resolve them.</p>}
    {preview.requiresOverwriteAcknowledgement && <label className="acknowledgement">
      <input type="checkbox" checked={acknowledged} disabled={consumed || !!model.busy}
        onChange={(event) => setAcknowledged(event.target.checked)} />
      <span>I acknowledge overwriting the existing files covered by this frozen restore preview.</span>
    </label>}
    {consumed && !model.busy && <p className="error-text">This restore preview has been submitted. Close and request a fresh preview before trying again.</p>}
    <div className="modal-actions">
      <Button variant="secondary" disabled={!!model.busy} onClick={onClose}>Cancel</Button>
      <Button icon="download" disabled={!canUse(model) || consumed || (preview.blockingConflicts ?? 0) > 0 || (preview.requiresOverwriteAcknowledgement && !acknowledged)}
        onClick={() => { void confirmRestore() }}>Restore with native confirmation</Button>
    </div>
  </Dialog>
}

function BundleBrowser({ provider, model }: { provider: Provider; model: QuickSave }) {
  const [result, setResult] = useState<CatalogPage<Bundle> | null>(null)
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined])
  const [selected, setSelected] = useState<Bundle | null>(null)
  const [browseFiles, setBrowseFiles] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [preview, setPreview] = useState<DeletePreview | null>(null)
  const [restoreMode, setRestoreMode] = useState<RestoreMode>('create_new')
  const [restore, setRestore] = useState<{ preview: RestorePreview; plan: RestorePlan; bundle: Bundle } | null>(null)
  const [round, setRound] = useState(0)
  const [historyApp, setHistoryApp] = useState<{ id: string; name: string } | null>(null)
  const [pendingOpen, setPendingOpen] = useState(false)
  const cursor = cursors[cursors.length - 1]
  function refresh() { setCursors([undefined]); setRound((value) => value + 1) }
  useEffect(() => {
    let disposed = false
    setLoading(true); setError(null); setResult(null); setSelected(null); setBrowseFiles(false); setPreview(null); setRestore(null)
    void (historyApp ? api.history(provider.id, historyApp.id, cursor) : api.bundles(provider.id, cursor)).then((next) => {
      if (disposed) return
      if (next.items.some((item) => item.providerId !== provider.id)) throw new Error('The native bundle provider does not match this connection.')
      setResult(next)
    }).catch((reason) => { if (!disposed) setError(safeError(reason)) })
      .finally(() => { if (!disposed) setLoading(false) })
    return () => { disposed = true }
  }, [provider.id, cursor, round, historyApp?.id])
  async function download(fileIds?: string[]) {
    if (!selected) return
    // Capture source, subset and mode before awaiting a native picker/consent.
    const source = selected
    const mode = restoreMode
    const selectedFileIds = fileIds ? [...fileIds] : undefined
    const destination = await model.pick(() => chooseFolder('Choose a restore destination'))
    if (!destination) return
    const plan: RestorePlan = {
      providerId: provider.id, bundleId: source.id, appId: source.appId, destination, mode,
      ...(selectedFileIds ? { fileIds: selectedFileIds } : {}),
    }
    const result = await model.run('preview_restore', plan)
    if (result === undefined) return
    try { setRestore({ preview: normalizeRestorePreview(result, plan), plan, bundle: source }) }
    catch (reason) { model.reportError(reason) }
  }
  async function previewDelete() {
    if (!selected || provider.readOnly) return
    const value = await model.run('preview_delete', { providerId: provider.id, bundleId: selected.id, appId: selected.appId })
    if (value === undefined) return
    try {
      setPreview(normalizeDeletePreview(value, { providerId: provider.id, bundleId: selected.id, appId: selected.appId }))
    } catch (reason) { model.reportError(reason) }
  }
  return <section className="card bundle-browser" aria-label={`Backups on ${provider.name}`}>
    <div className="card-heading"><h2 className="truncate" title={provider.name}>{provider.name}</h2>
      <Button icon="refresh" variant="ghost" disabled={loading || !canUse(model)}
        onClick={refresh}>Refresh</Button></div>
    <div className="catalog-toolbar">
      {historyApp && <div className="section-heading"><h3 className="truncate" title={historyApp.name}>App history: {historyApp.name}</h3>
        <Button variant="ghost" onClick={() => { setHistoryApp(null); setCursors([undefined]) }}>All backups</Button></div>}
      <button type="button" className="text-button" aria-expanded={pendingOpen}
        onClick={() => setPendingOpen(!pendingOpen)}>{pendingOpen ? 'Hide pending deletions' : 'Show pending deletions'}</button>
    </div>
    {pendingOpen && <PendingDeletions key={provider.id} providerId={provider.id} />}
    {loading && <p className="empty-line" role="status">Loading backups…</p>}
    {error && <InlineError message={error} onRetry={refresh} />}
    {result && <CatalogFreshnessNote page={result} />}
    {result && (result.items.length ? <>
      <ul className="bundle-list">{result.items.map((bundle) => <li key={bundle.id}>
        <button type="button" className={`bundle-choice ${selected?.id === bundle.id ? 'selected' : ''}`}
          aria-pressed={selected?.id === bundle.id} onClick={() => {
            setSelected(bundle); setBrowseFiles(false); setPreview(null); setRestore(null); setRestoreMode('create_new')
          }}>
          <Icon name="folder" size={21} />
          <span className="bundle-copy"><strong className="truncate" title={bundle.name}>{bundle.name}</strong>
            <span>{date(bundle.createdAt ?? null)} · {number(bundle.fileCount ?? null)} files</span>
            <span>{backupScope(bundle)}{bundle.currentHead ? ' · Current head' : ''}</span></span>
          <span className="bundle-size">{bytes(bundle.logicalBytes ?? null)}</span><Icon name="chevron" size={17} />
        </button>
      </li>)}</ul>
      <div className="pagination"><span className="muted">Page {cursors.length}</span>
        <Button variant="ghost" disabled={loading || cursors.length === 1}
          onClick={() => setCursors((previous) => previous.slice(0, -1))}>Previous</Button>
        <Button variant="ghost" disabled={loading || !result.nextCursor || cursors.length >= 1_000}
          onClick={() => {
            if (result.nextCursor && !cursors.includes(result.nextCursor)) setCursors((previous) => [...previous, result.nextCursor!])
            else setError('The native backup cursor did not advance. Refresh from the first page.')
          }}>Next</Button>
      </div>
    </> : <p className="empty-line">No backups reported on this provider.</p>)}
    {selected && <div className="selected-bundle">
      <div className="section-heading"><div className="min-width-zero">
        <h3 className="truncate" title={selected.name}>{selected.name}</h3>
        {selected.compatibility && <p className="muted">{selected.compatibility}</p>}
      </div><div className="row-actions">
        <Button icon="download" disabled={!canUse(model)} onClick={() => { void download() }}>Download backup</Button>
        <Button icon="trash" variant="ghost" disabled={!canUse(model) || provider.readOnly}
          onClick={() => { void previewDelete() }}>Delete cloud backup</Button>
      </div></div>
      <BundleCoverageNote bundle={selected} />
      {!historyApp && <button type="button" className="text-button" onClick={() => {
        setHistoryApp({ id: selected.appId, name: selected.name }); setCursors([undefined])
      }}>View app history</button>}
      <details className="dependency-list">
        <summary>Restore options and backup details</summary>
        <label className="field">Restore mode
          <select value={restoreMode} disabled={!canUse(model)} onChange={(event) => setRestoreMode(event.target.value as RestoreMode)}>
            {Object.entries(restoreModes).map(([value, label]) => <option value={value} key={value}>{label}</option>)}
          </select>
        </label>
        <BundleIdentities bundle={selected} />
      </details>
      <button type="button" className="text-button" aria-expanded={browseFiles}
        onClick={() => setBrowseFiles(!browseFiles)}>{browseFiles ? 'Hide files' : 'Browse individual files'}</button>
      {browseFiles && <FileBrowser key={selected.id} label={`Files in ${selected.name}`} disabled={!canUse(model)}
        load={(next) => api.bundleFiles(provider.id, selected.id, selected.appId, next)}
        transferLabel="Download" onTransfer={download} />}
      {preview && <DeleteDialog preview={preview} bundle={selected} model={model}
        onClose={() => setPreview(null)} onDeleted={refresh} />}
      {restore && <RestoreDialog key={restore.preview.previewId} preview={restore.preview} plan={restore.plan} bundle={restore.bundle}
        model={model} onClose={() => setRestore(null)} />}
    </div>}
  </section>
}

function RestorePage({ model, onConnect }: { model: QuickSave; onConnect: () => void }) {
  const providers = connected(model)
  const [providerId, setProviderId] = useState<string | null>(null)
  const selected = providers.find((provider) => provider.id === providerId)
  return <div className="page-stack">
    <div className="section-heading"><h2>Connected providers</h2>
      <Button variant="secondary" icon="plus" disabled={!canUse(model)} onClick={onConnect}>Connect providers</Button></div>
    {providers.length ? <div className="provider-cards">{providers.map((provider) => <button type="button" key={provider.id}
      className={`provider-card ${selected?.id === provider.id ? 'selected' : ''}`} aria-pressed={selected?.id === provider.id}
      onClick={() => setProviderId(provider.id)}>
      <Icon name="cloud" size={24} /><span className="provider-copy">
        <strong className="truncate" title={provider.name}>{provider.name}</strong>
        <span>{provider.kind}{provider.readOnly ? ' · Read-only' : ''}</span></span><Icon name="chevron" size={16} />
    </button>)}</div> : <p className="empty-line card">Connect a provider to browse its backups.</p>}
    {selected && <BundleBrowser key={selected.id} provider={selected} model={model} />}
  </div>
}

export default function App() {
  const model = useQuickSave()
  const [page, setPage] = useState<Page>('overview')
  const [providersOpen, setProvidersOpen] = useState(false)
  const scroll = useRef<HTMLDivElement>(null)
  const current = pages.find((entry) => entry.id === page)!
  function navigate(next: Page) {
    setPage(next)
    if (scroll.current) scroll.current.scrollTop = 0
  }
  return <div className="app-shell">
    <a className="skip-link" href="#main-content">Skip to content</a>
    <aside className="sidebar">
      <Brand />
      <nav className="main-nav" aria-label="Main navigation">{pages.map((entry) => <button key={entry.id} type="button"
        className={page === entry.id ? 'active' : ''} aria-current={page === entry.id ? 'page' : undefined}
        onClick={() => navigate(entry.id)}>
        <Icon name={entry.icon} size={21} /><span>{entry.label}</span>
      </button>)}</nav>
      <div className="sidebar-bottom"><Icon name="lock" size={16} /><span>Your files stay yours.</span></div>
    </aside>
    <div className="main-shell">
      <header className="topbar"><span className="breadcrumb">Workspace / <strong>{current.label}</strong></span>
        <span className="runtime-label"><span className={`status-dot ${model.ready ? 'status-ready' : ''}`} />
          {model.native ? model.loading ? 'Connecting…' : model.error ? 'Unavailable' : 'Desktop' : 'Browser preview'}</span></header>
      <div className="main-scroll" ref={scroll}>
        <main className="page-content" id="main-content" tabIndex={-1}>
          <div className="page-heading"><h1>{current.label}</h1></div>
          {!model.native && <p className="runtime-banner" role="status">Browser preview only. Open QuickSave desktop to connect providers or access files.</p>}
          {model.error && <InlineError message={model.error} onRetry={() => { void model.refresh() }} />}
          {model.notice && !providersOpen && <div className="notice" role="alert"><p>{model.notice}</p>
            <button className="icon-button" type="button" aria-label="Dismiss message" onClick={model.dismissNotice}><Icon name="close" size={18} /></button></div>}
          {model.loading && <p className="loading-status" role="status">Loading workspace…</p>}
          {page === 'overview' && <Overview model={model} onConnect={() => setProvidersOpen(true)} navigate={navigate} />}
          {page === 'backup' && <BackupPage model={model} />}
          {page === 'restore' && <RestorePage model={model} onConnect={() => setProvidersOpen(true)} />}
          <ActivityList model={model} />
          <BatchActivityList model={model} />
        </main>
      </div>
    </div>
    {providersOpen && <ProviderDialog model={model} onClose={() => setProvidersOpen(false)} />}
  </div>
}
