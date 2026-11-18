// SPDX-License-Identifier: GPL-3.0-only
import { useEffect, useState } from 'react'
import { api, safeError, type Bundle, type CatalogPage, type PendingDeletion } from './api'
import { bytes, date, number } from './format'
import { Button, InlineError } from './ui'

export function backupScope(bundle: Bundle): string {
  if (bundle.completeApplication === true && bundle.completeness === 'complete_application') return 'Complete-application coverage'
  if (bundle.completeness === 'selected_files') return 'Selected files only'
  if (bundle.completeness === 'approved_software') return 'Approved roots only'
  if (bundle.completeness === 'personal_state') return 'Personal state only'
  if (bundle.mode === 'custom' || bundle.subset === true) return 'Custom / selected scope'
  return 'Coverage unknown'
}

export function CatalogFreshnessNote({ page }: { page: CatalogPage<unknown> }) {
  const timestamp = page.freshness?.observedAt
  const observed = timestamp && Number.isFinite(Date.parse(timestamp)) ? timestamp : undefined
  return <div className="catalog-freshness">
    <p className="muted">{observed ? `Catalog observed: ${date(observed)}` : 'Catalog freshness unknown — no native observation time reported.'}</p>
    <details className="dependency-list">
      <summary>Catalog observation details</summary>
      <dl className="backup-identities">
        <div><dt>Source</dt><dd>{page.freshness?.source || 'Not reported'}</dd></div>
        <div><dt>Revision</dt><dd className="truncate" title={page.revision}>{page.revision ?? 'Not reported'}</dd></div>
        <div><dt>Catalog commit</dt><dd className="truncate" title={page.catalogCommitId}>{page.catalogCommitId ?? 'Not reported'}</dd></div>
        {page.freshness?.refreshStartedAt && <div><dt>Refresh started</dt><dd>{date(page.freshness.refreshStartedAt)}</dd></div>}
      </dl>
      <p className="muted">Browse metadata is not execution authority. Restore and deletion require a fresh native frozen preview.</p>
    </details>
  </div>
}

export function BundleCoverageNote({ bundle }: { bundle: Bundle }) {
  const complete = bundle.completeApplication === true && bundle.completeness === 'complete_application'
  return <div className="backup-coverage">
    <p className={complete ? 'muted' : 'coverage-warning'}>{backupScope(bundle)}{complete
      ? '. Application reconstruction still requires native restore validation.'
      : ' — not verified as a complete application.'}</p>
    <p className="muted">{bundle.readiness
      ? `${bundle.readiness.metadataVerified ? 'Metadata verified' : 'Metadata verification not reported'} · ${bundle.readiness.filesAvailable ? 'Files reported available' : 'File availability not verified'} · ${bundle.readiness.applicationReady ? 'Native application readiness reported' : 'Application reconstruction not verified'}.`
      : 'Restore readiness unknown. Native validation is required.'}</p>
  </div>
}

export function BundleIdentities({ bundle }: { bundle: Bundle }) {
  const mode = bundle.mode === 'complete_application' ? 'Complete application (catalog mode)'
    : bundle.mode === 'personal_state' ? 'Personal state (catalog mode)'
      : bundle.mode === 'custom' ? 'Custom (catalog mode)' : 'Not reported'
  return <dl className="backup-identities">
    <div><dt>Bundle ID</dt><dd className="truncate" title={bundle.id}>{bundle.id}</dd></div>
    <div><dt>Original app ID</dt><dd className="truncate" title={bundle.appId}>{bundle.appId}</dd></div>
    <div><dt>Source instance</dt><dd className="truncate" title={bundle.sourceInstanceId}>{bundle.sourceInstanceId ?? 'Not reported'}</dd></div>
    <div><dt>Commit</dt><dd className="truncate" title={bundle.commitId}>{bundle.commitId ?? 'Not reported'}</dd></div>
    <div><dt>Parent bundle</dt><dd className="truncate" title={bundle.parentBundleId ?? undefined}>
      {bundle.parentBundleId === null ? 'No parent reported' : bundle.parentBundleId ?? 'Unknown'}</dd></div>
    <div><dt>Mode</dt><dd>{mode}</dd></div>
    <div><dt>Catalog heads</dt><dd>{[
      bundle.currentHead === true && 'Current head',
      bundle.currentCompleteHead === true && 'Complete-mode head (not completeness proof)',
      bundle.currentPersonalStateHead === true && 'Personal-state head',
    ].filter(Boolean).join(' · ') || (bundle.currentHead === false ? 'Historical generation' : 'Head status unknown')}</dd></div>
    <div><dt>Files</dt><dd>{number(bundle.fileCount ?? null)}</dd></div>
    <div><dt>Logical data</dt><dd>{bytes(bundle.logicalBytes ?? null)}</dd></div>
    {bundle.storedIncrementalBytes !== undefined && <div><dt>Stored incremental data</dt><dd>{bytes(bundle.storedIncrementalBytes)}</dd></div>}
    {bundle.tombstoneCount !== undefined && <div><dt>Deletion-state entries</dt><dd>{number(bundle.tombstoneCount)}</dd></div>}
    {bundle.platform && <div><dt>Source platform</dt><dd>{bundle.platform}</dd></div>}
    {bundle.sourceBundleId && <div><dt>Shared source bundle</dt><dd className="truncate" title={bundle.sourceBundleId}>{bundle.sourceBundleId}</dd></div>}
    {bundle.sourceAppId && <div><dt>Shared source app</dt><dd className="truncate" title={bundle.sourceAppId}>{bundle.sourceAppId}</dd></div>}
  </dl>
}

export function PendingDeletions({ providerId }: { providerId: string }) {
  const [result, setResult] = useState<CatalogPage<PendingDeletion> | null>(null)
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [round, setRound] = useState(0)
  const cursor = cursors[cursors.length - 1]
  function refresh() { setCursors([undefined]); setRound((value) => value + 1) }
  useEffect(() => {
    let disposed = false
    setLoading(true); setError(null); setResult(null)
    void api.pendingDeletions(providerId, cursor).then((page) => {
      if (!disposed) setResult(page)
    }).catch((reason) => {
      if (!disposed) setError(safeError(reason))
    }).finally(() => { if (!disposed) setLoading(false) })
    return () => { disposed = true }
  }, [providerId, cursor, round])
  return <section className="pending-deletions" aria-label="Pending deletions" aria-busy={loading}>
    <div className="section-heading"><h3>Pending deletion plans</h3>
      <Button variant="ghost" icon="refresh" disabled={loading} onClick={refresh}>Refresh pending plans</Button>
    </div>
    <p className="muted">Nothing here is deleted automatically. This list is not deletion approval; execution requires an authenticated native plan and separate confirmation.</p>
    {loading && <p className="empty-line" role="status">Loading pending plans…</p>}
    {error && <InlineError message={error} onRetry={refresh} />}
    {result && <>
      <CatalogFreshnessNote page={result} />
      {result.items.length ? <ul className="pending-plan-list">{result.items.map((plan) => <li key={plan.planId}>
        <details>
          <summary><span className="truncate" title={plan.planId}>Plan {plan.planId}</span></summary>
          <dl className="backup-identities">
            <div><dt>Source plan ID</dt><dd className="truncate" title={plan.planId}>{plan.planId}</dd></div>
            {plan.operationId && <div><dt>Original operation</dt><dd className="truncate" title={plan.operationId}>{plan.operationId}</dd></div>}
            {plan.digest && <div><dt>Plan digest</dt><dd className="truncate" title={plan.digest}>{plan.digest}</dd></div>}
            <div><dt>Requested backups</dt><dd>{number(plan.requestedCount ?? null)}</dd></div>
            <div><dt>Affected backups</dt><dd>{number(plan.affectedCount ?? null)}</dd></div>
            <div><dt>Dependent backups</dt><dd>{plan.dependenciesKnown ? number(plan.dependentCount ?? null) : 'Unknown — load the authenticated native plan first'}</dd></div>
            <div><dt>Logical data</dt><dd>{bytes(plan.logicalBytes ?? null)}</dd></div>
            <div><dt>Physical data</dt><dd>{bytes(plan.physicalBytes ?? null)}</dd></div>
          </dl>
          {!!plan.names.length && <ul>{plan.names.map((name, index) => <li key={index} className="truncate" title={name}>{name}</li>)}</ul>}
          {plan.nameCount !== undefined && plan.nameCount > plan.names.length && <p className="muted">
            Showing {number(plan.names.length)} of {number(plan.nameCount)} names.</p>}
          <p className="muted">{plan.detailsAvailable
            ? 'Summary only. Exact affected app, bundle and commit identities must be revalidated natively before deletion.'
            : 'Full plan details are unavailable in this catalog. Dependencies and sizes remain unknown.'}</p>
        </details>
      </li>)}</ul> : <p className="empty-line">No pending deletion plans reported in this catalog.</p>}
      <div className="pagination"><span className="muted">Pending plans · Page {cursors.length}</span>
        <Button variant="ghost" disabled={loading || cursors.length === 1}
          onClick={() => setCursors((previous) => previous.slice(0, -1))}>Previous pending plans</Button>
        <Button variant="ghost" disabled={loading || !result.nextCursor || cursors.length >= 1_000}
          onClick={() => {
            if (result.nextCursor && !cursors.includes(result.nextCursor)) setCursors((previous) => [...previous, result.nextCursor!])
            else setError('The native pending-plan cursor did not advance. Refresh from the first page.')
          }}>Next pending plans</Button>
      </div>
    </>}
  </section>
}
