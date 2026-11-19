// SPDX-License-Identifier: GPL-3.0-only
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { api, nativeRuntime, safeError, type VaultStatus, type VaultReadiness } from './api'
import { Button, InlineError } from './ui'

/** No workspace hooks mount behind this gate until the user explicitly proceeds.
 * Format metadata never authorizes a native vault read or proves OS unlock.
 */
export function VaultStartupGate({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(() => !nativeRuntime())
  const [status, setStatus] = useState<VaultStatus | null>(null)
  const [readiness, setReadiness] = useState<VaultReadiness | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [checking, setChecking] = useState(true)
  const mounted = useRef(false)
  const pending = useRef(false)
  const controller = useRef<AbortController | null>(null)

  async function check() {
    setChecking(true)
    setError('')
    try {
      const value = await api.vaultStatus()
      if (!mounted.current) return
      setStatus(value)
      if (value.format === 'encrypted_state') {
        const storage = await api.vaultReadiness()
        if (!mounted.current) return
        setReadiness(storage)
        if (storage.ready && !value.credentialSetupPending) setReady(true)
      }
    } catch (reason) {
      if (mounted.current) setError(safeError(reason))
    } finally {
      if (mounted.current) setChecking(false)
    }
  }
  useEffect(() => {
    mounted.current = true
    if (nativeRuntime()) void check()
    return () => {
      mounted.current = false
      controller.current?.abort()
    }
  }, [])

  async function setup(action: 'migrate_vault' | 'setup_local_tracking' | 'authorize_tracking_storage') {
    if (pending.current) return
    pending.current = true
    const abort = new AbortController()
    controller.current = abort
    setBusy(true)
    setError('')
    try {
      await api.action(action, {}, abort.signal)
      if (!mounted.current) return
      const value = await api.vaultStatus()
      if (!mounted.current) return
      if (value.format !== 'encrypted_state') {
        throw new Error('Encrypted state was not confirmed. Workspace startup remains paused.')
      }
      setStatus(value)
      const storage = await api.vaultReadiness()
      if (!mounted.current) return
      setReadiness(storage)
      if (!storage.ready) throw new Error(storage.issue)
      // Setup does not enable tracking: that remains a separate native opt-in.
      setReady(true)
    } catch (reason) {
      if (mounted.current) setError(`Local storage setup was not confirmed complete. ${safeError(reason)} No automatic retry or workspace startup was started. Old credential values are retained; no old item is deleted.`)
    } finally {
      pending.current = false
      if (mounted.current) setBusy(false)
    }
  }

  if (ready) return <>{children}</>
  return <main className="vault-startup" aria-labelledby="vault-startup-title">
    <section className="card page-stack">
      <h1 id="vault-startup-title">QuickSave secret storage</h1>
      {checking ? <p role="status">Checking local storage format…</p> : <>
        {status?.format === 'legacy' && <>
          <p>Set up encrypted local tracking storage without importing cloud credentials. One old device signing key, if present, may need native approval; provider passwords stay pending and locked.</p>
          <p>This creates one QuickSave encryption-key and rollback-anchor item. It does not enable tracking, connect accounts, upload data, or grant file access. Tracking remains a separate opt-in.</p>
          {status.legacyMigrationLimitation && <p>{status.legacyMigrationLimitation}</p>}
          <Button disabled={busy || status.legacyInventorySupported === false} onClick={() => void setup('setup_local_tracking')}>
            Start local tracking
          </Button>
          <details>
            <summary>Advanced credential import</summary>
            <p>Importing all old credentials may require several native approvals for provider passwords and repository keys. No old credential values are deleted.</p>
            <Button variant="secondary" disabled={busy || status.legacyInventorySupported === false} onClick={() => void setup('migrate_vault')}>Import all old credentials</Button>
          </details>
          <Button variant="secondary" disabled={busy} onClick={() => setReady(true)}>Continue without setup</Button>
          <p className="muted">Continuing without setup does not unlock storage or guarantee tracking works. Nothing starts while you remain here.</p>
        </>}
        {status?.format === 'encrypted_state' && <>
          {status.legacyMigrationLimitation && <p>{status.legacyMigrationLimitation}</p>}
          {readiness?.ready ? <>
            <h2>Local tracking is ready</h2>
            <p>Old cloud credentials remain pending. Local tracking does not require importing them.</p>
            <Button disabled={busy} onClick={() => setReady(true)}>Continue local tracking</Button>
            <Button variant="secondary" disabled={busy || status.legacyInventorySupported === false} onClick={() => void setup('migrate_vault')}>Import remaining credentials</Button>
          </> : <>
            <p>{readiness?.issue ?? 'Local tracking storage readiness has not been verified.'}</p>
            <p>Authorize only the existing QuickSave native encryption item. Background access may require Always Allow. This does not import cloud credentials or reset keys.</p>
            <Button disabled={busy} onClick={() => void setup('authorize_tracking_storage')}>Authorize local tracking storage</Button>
          </>}
        </>}
        {!status && <Button disabled={busy} onClick={() => void check()}>Retry local format check</Button>}
      </>}
      {error && <InlineError message={error} />}
      {error && status && <p>Review the diagnostic before trying again. No retry is automatic; closing QuickSave does not delete old credential items.</p>}
    </section>
  </main>
}
