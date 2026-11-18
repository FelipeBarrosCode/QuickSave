// SPDX-License-Identifier: GPL-3.0-only
import { useEffect, useRef, useState } from 'react'
import {
  api, normalizeUploadBatchPreview, safeError,
  type BatchReference, type BatchStatus, type UploadBatchPlan, type UploadBatchPreview,
} from './api'
import { bytes, number } from './format'
import { Button, Dialog, InlineError } from './ui'
import { MAX_POLL_REQUESTS, POLL_INTERVAL_MS, type QuickSave } from './useQuickSave'

type SelectedApp = { id: string; name: string }
const usable = (model: QuickSave) => model.ready && !model.busy

function UploadBatchDialog({ preview, providerName, selected, model, onClose, onUploaded }: {
  preview: UploadBatchPreview; providerName: string; selected: SelectedApp[] | null
  model: QuickSave; onClose: () => void; onUploaded: () => void
}) {
  const [consumed, setConsumed] = useState(false)
  async function upload() {
    if (consumed) return
    setConsumed(true)
    const result = await model.run('upload_all', { planSetId: preview.planSetId })
    if (result !== undefined) { onUploaded(); onClose() }
  }
  const names = preview.sampleNames ?? selected?.slice(0, 16).map((item) => item.name)
  return <Dialog title="Review batch upload" busy={!!model.busy} onClose={onClose}>
    <p className="dialog-note">Review the exact native-frozen app set. Local files are kept. No upload starts until you confirm.</p>
    <div className="delete-summary"><strong>{number(preview.softwareCount)} apps · {selected ? 'Selected apps' : 'All native-approved apps'}</strong>
      <span className="truncate" title={providerName}>{providerName}</span>
      {preview.jobCount !== undefined && <span>{number(preview.jobCount)} native jobs</span>}
      <span>{preview.fileCount === undefined ? 'File count unknown until native capture' : `${number(preview.fileCount)} files`}</span>
      <span>{preview.logicalBytes === undefined ? 'Byte total unknown until native capture' : bytes(preview.logicalBytes)}</span>
    </div>
    <p className="preview-metric muted">The app identities and approved roots are frozen, not an app-atomic snapshot. Native capture and validation happen for each original app operation.</p>
    {preview.summary && <p className="preview-metric muted">{preview.summary}</p>}
    {!!names?.length && <details className="dependency-list"><summary>{preview.sampleNames ? 'Native app sample' : 'Requested app sample'} ({names.length})</summary>
      <ul>{names.map((name, index) => <li key={index} className="truncate" title={name}>{name}</li>)}</ul>
      {preview.softwareCount > names.length && <p className="muted">Showing {number(names.length)} of {number(preview.softwareCount)} apps. The native plan retains every exact identity.</p>}
    </details>}
    <details className="dependency-list"><summary>Frozen plan identity</summary>
      <dl className="backup-identities"><div><dt>Plan-set ID</dt><dd className="truncate" title={preview.planSetId}>{preview.planSetId}</dd></div>
        <div><dt>Provider ID</dt><dd className="truncate" title={preview.providerId}>{preview.providerId}</dd></div>
      </dl>
    </details>
    {consumed && !model.busy && <p className="error-text">This plan has been submitted. Close and create a fresh preview before trying again.</p>}
    <div className="modal-actions"><Button variant="secondary" disabled={!!model.busy} onClick={onClose}>Cancel</Button>
      <Button icon="backup" disabled={!usable(model) || consumed} onClick={() => { void upload() }}>Upload frozen app set</Button></div>
  </Dialog>
}

export function UploadBatchControls({ model, selected, onUploaded, onClear }: {
  model: QuickSave; selected: SelectedApp[]; onUploaded: () => void; onClear: () => void
}) {
  const providers = model.dashboard?.providers.filter((provider) => provider.status === 'connected') ?? []
  const [chosenProviderId, setChosenProviderId] = useState<string | null>(null)
  const provider = providers.find((item) => item.id === chosenProviderId)
    ?? (chosenProviderId === null ? providers.find((item) => !item.readOnly) : undefined)
  const [review, setReview] = useState<{
    preview: UploadBatchPreview; providerName: string; selected: SelectedApp[] | null
  } | null>(null)
  async function previewUpload(all: boolean) {
    if (!provider || provider.readOnly || (!all && !selected.length)) return
    const requested = all ? null : selected.map((item) => ({ ...item }))
    const plan: UploadBatchPlan = {
      providerId: provider.id, ...(requested ? { softwareIds: requested.map((item) => item.id) } : {}),
    }
    const providerName = provider.name
    const response = await model.run('preview_upload_all', plan)
    if (response === undefined) return
    try { setReview({ preview: normalizeUploadBatchPreview(response, plan), providerName, selected: requested }) }
    catch (reason) { model.reportError(reason) }
  }
  const disabled = !usable(model) || !provider || provider.readOnly
  return <section className="card batch-controls" aria-label="Batch upload">
    <div className="section-heading"><div className="min-width-zero"><h2>Upload apps</h2>
      <p className="muted">All apps means the native approved inventory bound to this provider, not only the visible or filtered rows.</p></div>
      <label className="field batch-provider">Batch provider
        <select value={provider?.id ?? ''} disabled={!usable(model) || !providers.length}
          onChange={(event) => setChosenProviderId(event.target.value)}>
          <option value="" disabled>Choose provider</option>
          {providers.map((item) => <option value={item.id} key={item.id}>{item.name}{item.readOnly ? ' (read-only)' : ''}</option>)}
        </select>
      </label>
    </div>
    <div className="row-actions">
      <Button icon="backup" variant="secondary" disabled={disabled} onClick={() => { void previewUpload(true) }}>Preview upload all</Button>
      <Button icon="backup" variant="secondary" disabled={disabled || !selected.length}
        onClick={() => { void previewUpload(false) }}>Preview selected apps{selected.length ? ` (${number(selected.length)})` : ''}</Button>
      {!!selected.length && <button className="text-button" type="button" disabled={!usable(model)} onClick={onClear}>Clear app selection</button>}
    </div>
    {provider?.readOnly && <p className="muted">This connection is read-only. Use the separate native “Enable uploads” grant in Connect providers.</p>}
    {!!selected.length && <p className="muted">Selected apps must already be assigned to this provider. Change an app’s provider separately; this batch cannot widen its native approval.</p>}
    {review && <UploadBatchDialog key={review.preview.planSetId} preview={review.preview}
      providerName={review.providerName} selected={review.selected} model={model}
      onClose={() => setReview(null)} onUploaded={onUploaded} />}
  </section>
}

function finished(status: BatchStatus): boolean {
  return ['completed', 'failed', 'cancelled', 'interrupted'].includes(status.state) && status.shutdownBlocked === false
}

export function useBatchStatus(reference: BatchReference) {
  const [status, setStatus] = useState<BatchStatus | null>(null)
  const [issue, setIssue] = useState<string | null>(null)
  const [round, setRound] = useState(0)
  const pending = useRef<{ key: string; request: Promise<BatchStatus> } | null>(null)
  useEffect(() => {
    let disposed = false
    let requests = 0
    let errors = 0
    let timer: ReturnType<typeof setTimeout> | undefined
    async function poll() {
      if (disposed) return
      if (requests >= MAX_POLL_REQUESTS) {
        setIssue('Batch checks paused after 600 requests. Resume status checks; no native work was cancelled.')
        return
      }
      requests += 1
      try {
        const key = `${reference.planSetId}/${reference.operationId}`
        if (!pending.current || pending.current.key !== key) {
          const request = api.batchStatus(reference.planSetId, reference.operationId)
          pending.current = { key, request }
          void request.finally(() => {
            if (pending.current?.request === request) pending.current = null
          }).catch(() => {})
        }
        const next = await pending.current.request
        if (disposed) return
        errors = 0; setStatus(next); setIssue(null)
        if (finished(next)) return
      } catch (reason) {
        if (disposed) return
        errors += 1
        setIssue(`Batch status is unavailable. Native work may still be running. ${safeError(reason)}`)
        if (errors >= 3) return
      }
      if (!disposed) timer = setTimeout(() => { void poll() }, POLL_INTERVAL_MS)
    }
    void poll()
    return () => { disposed = true; if (timer !== undefined) clearTimeout(timer) }
  }, [reference.planSetId, reference.operationId, round])
  return { status, issue, refresh: () => { setIssue(null); setRound((value) => value + 1) } }
}

function BatchActivityRow({ reference, model }: { reference: BatchReference; model: QuickSave }) {
  const { status, issue, refresh } = useBatchStatus(reference)
  async function control(action: 'cancel' | 'retry') {
    const result = await model.run(action, { operationId: reference.operationId })
    if (result !== undefined) refresh()
  }
  return <li className="batch-activity-row">
    <details>
      <summary><strong>App batch upload</strong><span className="activity-state">{status?.state ?? 'Status unknown'}</span>
        {status && status.childCount !== undefined && <span className="muted">{number(status.completed ?? null)} / {number(status.childCount)} apps completed</span>}</summary>
      <div className="batch-activity-details">
        <dl className="backup-identities">
          <div><dt>Original operation</dt><dd className="truncate" title={reference.operationId}>{reference.operationId}</dd></div>
          <div><dt>Frozen plan set</dt><dd className="truncate" title={reference.planSetId}>{reference.planSetId}</dd></div>
        </dl>
        {status && <>
          {status.childCount !== undefined ? <p className="muted">{number(status.jobCount ?? null)} jobs · {number(status.active ?? null)} active · {number(status.notStarted ?? null)} not started · {number(status.failed ?? null)} failed · {number(status.cancelled ?? null)} cancelled · {number(status.interrupted ?? null)} interrupted · {number(status.unknown ?? null)} unknown · {number(status.awaitingFinalization ?? null)} awaiting finalization</p>
            : <p className="muted">Native job totals not reported yet.</p>}
          {status.progress.length > 0 && <ul className="batch-progress">{status.progress.map((progress, index) => <li key={index}>
            <span>{progress.phase}: {number(progress.completed)}{progress.total !== undefined ? ` / ${number(progress.total)}` : ''} {progress.unit}</span>
            <span className="muted"> · {number(progress.reportingChildren)} reporting apps</span>
          </li>)}</ul>}
          {status.cancelRequested && <p className="muted">Native cancellation requested; waiting for original workers to drain.</p>}
          {status.shutdownBlocked && <p className="muted">Native work has not drained. Keep QuickSave open.</p>}
        </>}
        {issue && <InlineError message={issue} onRetry={refresh} />}
        <div className="row-actions">
          <Button variant="ghost" icon="refresh" onClick={refresh}>Check batch status</Button>
          {status?.canCancel && !status.cancelRequested && <Button variant="secondary" disabled={!usable(model)}
            onClick={() => { void control('cancel') }}>Cancel original app batch</Button>}
          {status?.canRetry && <Button variant="secondary" disabled={!usable(model)}
            onClick={() => { void control('retry') }}>Retry original app batch</Button>}
        </div>
      </div>
    </details>
  </li>
}

export function BatchActivityList({ model }: { model: QuickSave }) {
  const [showAll, setShowAll] = useState(false)
  if (!model.batches.length) return null
  return <section className="activity-section" aria-label="Batch uploads">
    <div className="section-heading"><h2>App batch activity</h2>
      {model.batches.length > 3 && <button className="text-button" type="button" onClick={() => setShowAll(!showAll)}>
        {showAll ? 'Show fewer batches' : `Show batches (${model.batches.length})`}</button>}
    </div>
    <ul className="activity-list card">{model.batches.slice(0, showAll ? 64 : 3).map((reference) =>
      <BatchActivityRow key={reference.planSetId} reference={reference} model={model} />)}</ul>
  </section>
}
