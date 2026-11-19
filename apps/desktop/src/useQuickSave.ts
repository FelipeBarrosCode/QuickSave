// SPDX-License-Identifier: GPL-3.0-only
import { useCallback, useEffect, useRef, useState } from 'react'
import {
  api, nativeRuntime, normalizeDashboard, record, safeError, terminal,
  type Action, type ActionParams, type Activity, type AppTracking, type BatchReference, type Dashboard,
} from './api'

export const POLL_INTERVAL_MS = 2_000
export const MAX_POLL_REQUESTS = 600
const MAX_POLL_ERRORS = 3

function mergeActivity(previous: Activity[], next: Activity[]) {
  const missing = previous.filter((item) => !terminal(item.state)
    && !next.some((current) => current.id === item.id))
  // Do not let a full page of newer history evict unfinished known work.
  const combined = [...missing, ...next.filter((item) => !terminal(item.state)),
    ...next.filter((item) => terminal(item.state))]
  return { items: combined.slice(0, 128), missing: missing.length > 0, truncated: combined.length > 128 }
}

export function useQuickSave() {
  const [native] = useState(nativeRuntime)
  const [dashboard, setDashboard] = useState<Dashboard | null>(null)
  const [loading, setLoading] = useState(native)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [busy, setBusy] = useState<Action | 'picker' | null>(null)
  const [activity, setActivity] = useState<Activity[]>([])
  const [batches, setBatches] = useState<BatchReference[]>([])
  const [tracking, setTracking] = useState<AppTracking | null>(null)
  const [trackingError, setTrackingError] = useState<string | null>(null)
  const [trackingPollIssue, setTrackingPollIssue] = useState<string | null>(null)
  const [trackingRound, setTrackingRound] = useState(0)
  const [pollIssue, setPollIssue] = useState<string | null>(null)
  const [pollRound, setPollRound] = useState(0)
  const mounted = useRef(false)
  const lock = useRef(false)
  const pendingConsent = useRef<AbortController | null>(null)
  const refreshPromise = useRef<Promise<void> | null>(null)
  const trackingPromise = useRef<Promise<AppTracking> | null>(null)
  const activityPromise = useRef<Promise<Activity[]> | null>(null)
  const lastActivity = useRef<Activity[]>([])
  const activityBudget = useRef({ round: -1, requests: 0, errors: 0 })

  const rememberBatches = useCallback((references: BatchReference[]) => {
    if (!mounted.current || !references.length) return
    setBatches((previous) => [...references, ...previous.filter((item) =>
      !references.some((reference) => reference.planSetId === item.planSetId))].slice(0, 64))
  }, [])
  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false; pendingConsent.current?.abort() }
  }, [])

  const acceptDashboard = useCallback((next: Dashboard) => {
    if (!mounted.current) return
    const merged = mergeActivity(lastActivity.current, next.activity)
    const nextActivity = next.activityUnavailable ? lastActivity.current : merged.items
    setDashboard({ ...next, activity: nextActivity })
    setActivity(nextActivity)
    if (next.activityUnavailable) setPollIssue(next.activityIssue ?? 'History is unavailable; existing work is retained. Local tracking can continue.')
    else if (merged.missing) setPollIssue('Some unfinished work is absent from the latest status. Its last known state is retained; nothing was cancelled.'
      + (merged.truncated ? ' The display is limited to 128 rows; native history is retained.' : ''))
    else if (merged.truncated) setPollIssue('Activity exceeds the 128-row display limit. Native history is retained; no completion is inferred from omitted rows.')
    rememberBatches(nextActivity.filter((item) => item.planSetId).map((item) => ({
      planSetId: item.planSetId!, operationId: item.id, providerId: item.providerId,
    })))
    lastActivity.current = nextActivity
    setError(null)
  }, [rememberBatches])
  const readTracking = useCallback(() => {
    if (trackingPromise.current) return trackingPromise.current
    const pending = api.appTracking().finally(() => { trackingPromise.current = null })
    trackingPromise.current = pending
    return pending
  }, [])
  const readActivity = useCallback(() => {
    if (activityPromise.current) return activityPromise.current
    const pending = api.activity().finally(() => { activityPromise.current = null })
    activityPromise.current = pending
    return pending
  }, [])
  const refreshTracking = useCallback(async () => {
    if (!native || !mounted.current) return
    try {
      const next = await readTracking()
      if (mounted.current) { setTracking(next); setTrackingError(null) }
    } catch (reason) {
      if (mounted.current) setTrackingError(safeError(reason))
    }
  }, [native, readTracking])
  const refresh = useCallback(async () => {
    if (!native || !mounted.current) return
    if (refreshPromise.current) return refreshPromise.current
    const pending = (async () => {
      try {
        acceptDashboard(await api.dashboard())
      } catch (reason) {
        if (mounted.current) setError(safeError(reason))
      } finally {
        if (mounted.current) setLoading(false)
      }
    })()
    refreshPromise.current = pending
    try { await pending } finally { refreshPromise.current = null }
  }, [acceptDashboard, native])

  useEffect(() => { void refresh() }, [refresh])
  // The initial dashboard may be waiting on native Keychain consent. Do not
  // queue independent reads behind that dialog or exhaust the native workers.
  const workspaceReady = dashboard !== null && !loading
  useEffect(() => {
    if (workspaceReady) void refreshTracking()
  }, [workspaceReady, refreshTracking])

  useEffect(() => {
    if (!native || !tracking?.scanning) return
    let disposed = false
    let requests = 0
    let errors = 0
    let timer: ReturnType<typeof setTimeout> | undefined
    async function poll() {
      if (disposed) return
      if (requests >= MAX_POLL_REQUESTS) {
        setTrackingPollIssue('App-tracking checks paused after 600 requests. Resume to check native scanning; nothing was cancelled.')
        return
      }
      requests += 1
      try {
        const next = await readTracking()
        if (disposed) return
        errors = 0
        setTracking(next)
        setTrackingError(null)
        setTrackingPollIssue(null)
        if (!next.scanning) { await refresh(); return }
      } catch (reason) {
        if (disposed) return
        errors += 1
        if (errors >= MAX_POLL_ERRORS) {
          setTrackingPollIssue(`App-tracking status is unavailable after three checks. Native scanning may still be running. ${safeError(reason)}`)
          return
        }
      }
      if (!disposed) timer = setTimeout(() => { void poll() }, POLL_INTERVAL_MS)
    }
    timer = setTimeout(() => { void poll() }, POLL_INTERVAL_MS)
    return () => {
      disposed = true
      if (timer !== undefined) clearTimeout(timer)
    }
  }, [native, tracking?.scanning, trackingRound, refresh, readTracking])

  const hasActiveActivity = activity.some((item) => !terminal(item.state))
  useEffect(() => {
    if (!native || !workspaceReady) return
    let disposed = false
    if (activityBudget.current.round !== pollRound) {
      activityBudget.current = { round: pollRound, requests: 0, errors: 0 }
    }
    const budget = activityBudget.current
    let timer: ReturnType<typeof setTimeout> | undefined
    async function poll() {
      if (disposed) return
      if (budget.requests >= MAX_POLL_REQUESTS) {
        setPollIssue('Activity checks paused after 600 requests. Resume to check native work; nothing was cancelled.')
        return
      }
      budget.requests += 1
      try {
        const next = await readActivity()
        if (disposed) return
        budget.errors = 0
        setPollIssue(null)
        const completed = next.some((item) => terminal(item.state)
          && lastActivity.current.find((previous) => previous.id === item.id)?.state !== item.state)
        const merged = mergeActivity(lastActivity.current, next)
        lastActivity.current = merged.items
        setActivity(merged.items)
        rememberBatches(next.filter((item) => item.planSetId).map((item) => ({
          planSetId: item.planSetId!, operationId: item.id, providerId: item.providerId,
        })))
        if (completed) await refresh()
        if (merged.missing) {
          setPollIssue('Some unfinished work is absent from the latest status. Its last known state is retained; resume checks to review it. Nothing was cancelled.'
            + (merged.truncated ? ' The display is limited to 128 rows; native history is retained.' : ''))
          return
        }
        if (merged.truncated) {
          setPollIssue('Activity exceeds the 128-row display limit. Native history is retained; no completion is inferred from omitted rows.')
          return
        }
        // An idle/terminal workspace needs no 20-minute request countdown.
        // Poll again only for native-reported unfinished work, a new operation,
        // an explicit resume, or a new dashboard that discovers active work.
        if (!next.some((item) => !terminal(item.state))) return
      } catch (reason) {
        if (disposed) return
        budget.errors += 1
        if (budget.errors >= MAX_POLL_ERRORS) {
          setPollIssue(`Activity is unavailable after three checks. Native work may still be running. ${safeError(reason)}`)
          return
        }
      }
      // Schedule only after the previous request/refresh settles: no overlap.
      if (!disposed) timer = setTimeout(() => { void poll() }, POLL_INTERVAL_MS)
    }
    timer = setTimeout(() => { void poll() }, POLL_INTERVAL_MS)
    return () => {
      disposed = true
      if (timer !== undefined) clearTimeout(timer)
    }
  }, [native, workspaceReady, hasActiveActivity, pollRound, refresh, rememberBatches, readActivity])

  const reportError = useCallback((reason: unknown) => {
    if (mounted.current) setNotice(safeError(reason))
  }, [])

  async function run<A extends Action>(action: A, params: ActionParams[A]): Promise<unknown | undefined> {
    if (!mounted.current || !native || loading || error || lock.current) return undefined
    lock.current = true
    const consent = new AbortController()
    pendingConsent.current = consent
    setBusy(action)
    setNotice(null)
    try {
      const result = await api.action(action, params, consent.signal)
      if (!mounted.current) return undefined
      if (action === 'preview_delete' || action === 'preview_restore' || action === 'preview_upload_all'
        || action === 'discover_noland_import') return result
      // A newly accepted user operation gets its own bounded status budget.
      setPollIssue(null)
      setPollRound((round) => round + 1)
      if (action === 'upload_all') {
        const operationId = record(result)?.operationId
        if (typeof operationId === 'string' && operationId.length > 0 && operationId.length <= 4_096
          && !/[\u0000-\u001f\u007f]/.test(operationId)) {
          const planSetId = (params as ActionParams['upload_all']).planSetId
          rememberBatches([{ planSetId, operationId }])
        } else {
          reportError('The batch request was accepted, but its original operation ID is unavailable. Check native Activity; do not resubmit the plan.')
        }
        await refresh()
        return result
      }
      if (record(result)?.summary) acceptDashboard(normalizeDashboard(result))
      else {
        const id = record(result)?.operationId
        const batchControl = (action === 'cancel' || action === 'retry')
          && batches.some((batch) => batch.operationId === (params as ActionParams['cancel']).operationId)
        if (typeof id === 'string' && !batchControl) {
          try {
            const operation = await api.operation(id)
            if (mounted.current) {
              const merged = mergeActivity([], [operation, ...lastActivity.current.filter((item) => item.id !== operation.id)])
              lastActivity.current = merged.items
              setActivity(merged.items)
              if (merged.truncated) setPollIssue('Activity exceeds the 128-row display limit. Native history is retained; no completion is inferred from omitted rows.')
            }
          } catch (reason) {
            reportError(`The request was accepted; its status is unknown. ${safeError(reason)}`)
          }
        }
        await refresh()
      }
      if (action === 'enable_app_tracking' || action === 'refresh_app_tracking') {
        setTrackingPollIssue(null)
        setTrackingRound((round) => round + 1)
        await refreshTracking()
      }
      return result
    } catch (reason) {
      reportError(reason)
      // A native failure can follow configuration but precede health verification.
      // Refresh sanitized state so an unverified profile is shown as such, not
      // hidden or optimistically treated as connected.
      await refresh()
      return undefined
    } finally {
      lock.current = false
      pendingConsent.current = null
      if (mounted.current) setBusy(null)
    }
  }

  async function pick<T>(picker: () => Promise<T>): Promise<T | undefined> {
    if (!mounted.current || !native || loading || error || lock.current) return undefined
    lock.current = true
    setBusy('picker')
    try {
      const result = await picker()
      return mounted.current ? result : undefined
    } catch (reason) { reportError(reason); return undefined }
    finally { lock.current = false; if (mounted.current) setBusy(null) }
  }

  return {
    native, dashboard, activity, batches, tracking, trackingError, trackingPollIssue,
    loading, error, notice, busy, pollIssue,
    ready: native && !loading && !error && dashboard !== null,
    refresh, refreshTracking, run, pick, reportError,
    dismissNotice: () => setNotice(null),
    resumePolling: () => { setPollIssue(null); setPollRound((round) => round + 1); void refresh() },
    resumeTrackingPolling: () => {
      setTrackingPollIssue(null); setTrackingRound((round) => round + 1); void refreshTracking()
    },
  }
}
export type QuickSave = ReturnType<typeof useQuickSave>
