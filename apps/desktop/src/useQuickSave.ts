// SPDX-License-Identifier: GPL-3.0-only
import { useCallback, useEffect, useRef, useState } from 'react'
import {
  api, chooseFolder, chooseRecoveryKey, filesystemAvailability, nativeRuntime, operationId, record, safeError, terminal,
  type NativeReport, type Operation, type OperationKind, type RepositoryPaths, type Snapshot,
} from './api'

export type Workspace = RepositoryPaths & { source: string; destination: string }
export type Notice = { tone: 'success' | 'error' | 'info'; title: string; message: string }
type Busy = 'picker' | 'initialize' | 'snapshots' | 'backup' | 'restore' | null
type Tracking = { operation: Operation; paths: RepositoryPaths | null; paused: string | null; recovered: boolean }

// Bounded, serial polling: at most one native status request is pending.
export const POLL_INTERVAL_MS = 1_500
export const MAX_POLL_REQUESTS = 600
const MAX_STATUS_ERRORS = 3

export function useQuickSave() {
  const [native] = useState(nativeRuntime)
  const [report, setReport] = useState<NativeReport | null>(null)
  const [directories, setDirectories] = useState<NativeReport | null>(null)
  const [reportError, setReportError] = useState<string | null>(null)
  const [directoriesError, setDirectoriesError] = useState<string | null>(null)
  const [historyError, setHistoryError] = useState<string | null>(null)
  const [checking, setChecking] = useState(native)
  const [checksRound, setChecksRound] = useState(0)
  const [untrackedError, setUntrackedError] = useState<string | null>(null)
  const [workspace, setWorkspace] = useState<Workspace>({
    repository: '', source: '', keyFile: '', destination: '',
  })
  const [mode, setMode] = useState<'existing' | 'new'>('existing')
  const [verified, setVerified] = useState(false)
  const [snapshots, setSnapshots] = useState<Snapshot[]>([])
  const [snapshotsLoaded, setSnapshotsLoaded] = useState(false)
  const [busy, setBusy] = useState<Busy>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [tracking, setTracking] = useState<Tracking | null>(null)
  const [trackingRound, setTrackingRound] = useState(0)
  const lock = useRef(native)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false }
  }, [])

  useEffect(() => {
    if (!native) return
    let disposed = false
    lock.current = true
    setChecking(true)
    setReport(null)
    setDirectories(null)
    setReportError(null)
    setHistoryError(null)
    setDirectoriesError(null)
    async function loadReports() {
      const [capabilities, dirs, history] = await Promise.allSettled([api.capabilities(), api.directories(), api.history()])
      if (disposed) return
      if (capabilities.status === 'fulfilled' && record(capabilities.value)) {
        setReport(capabilities.value)
      } else {
        setReportError(capabilities.status === 'rejected'
          ? safeError(capabilities.reason) : 'The native capability report was not an object.')
      }
      if (dirs.status === 'fulfilled' && record(dirs.value)) setDirectories(dirs.value)
      else setDirectoriesError(dirs.status === 'rejected'
        ? safeError(dirs.reason) : 'The native directories report was not an object.')
      if (history.status === 'fulfilled') {
        const previous = history.value.find((operation) => !terminal(operation.state)) ?? history.value[0]
        setUntrackedError(null)
        setTracking(previous ? { operation: previous, paths: null, paused: null, recovered: true } : null)
        if (previous && !terminal(previous.state)) {
          setBusy(previous.kind === 'initialize' ? 'initialize' : previous.kind)
        } else {
          lock.current = false
          setBusy(null)
        }
      } else {
        setHistoryError(safeError(history.reason))
        lock.current = false
      }
      setChecking(false)
    }
    void loadReports()
    return () => { disposed = true }
  }, [native, checksRound])

  const filesystem = filesystemAvailability(report)
  const canRead = filesystem.canRead && !checking && !reportError
  const canWrite = filesystem.canWrite && !checking && !reportError && !historyError && !untrackedError
  const unavailableReason = reportError
    ? 'The native capability report is unavailable. Filesystem actions remain disabled until native checks succeed.'
    : historyError ? 'Operation history could not be checked. Mutations remain disabled until native checks succeed.'
      : filesystem.reason

  const fail = useCallback((title: string, error: unknown) => {
    if (mounted.current) setNotice({ tone: 'error', title, message: safeError(error) })
  }, [])

  const acquire = useCallback((action: Exclude<Busy, null>): boolean => {
    if (!native) {
      fail('Desktop application required', 'Native actions are unavailable in the browser preview.')
      return false
    }
    if ((action === 'initialize' || action === 'backup' || action === 'restore') && !canWrite) {
      fail('Native writes are unavailable', unavailableReason || 'Wait for native capability and operation-history checks to finish.')
      return false
    }
    if (action === 'snapshots' && !canRead) {
      fail('Native reads are unavailable', 'The platform report has not confirmed safe native reads.')
      return false
    }
    if (lock.current) {
      fail('An operation is already active', 'Wait for the current operation to finish. Paused tracking does not cancel it.')
      return false
    }
    lock.current = true
    setBusy(action)
    setNotice(null)
    return true
  }, [canRead, canWrite, fail, native, unavailableReason])

  const release = useCallback(() => {
    lock.current = false
    if (mounted.current) setBusy(null)
  }, [])

  const pathsReady = workspace.repository.length > 0 && workspace.keyFile.length > 0
  const active = tracking !== null && !terminal(tracking.operation.state)
  const working = checking || busy !== null || active || untrackedError !== null

  async function pick(field: keyof Workspace) {
    if (!acquire('picker')) return
    try {
      const path = field === 'keyFile'
        ? await chooseRecoveryKey(mode === 'new')
        : await chooseFolder({
          repository: mode === 'new' ? 'Choose an empty folder for the new repository' : 'Choose a QuickSave repository folder',
          source: 'Choose the folder to back up',
          destination: 'Choose an empty restore destination',
        }[field])
      if (!path || !mounted.current) return
      setWorkspace((previous) => ({ ...previous, [field]: path }))
      if (field === 'repository' || field === 'keyFile') {
        setSnapshots([])
        setSnapshotsLoaded(false)
        setVerified(false)
      }
    } catch (error) {
      fail('The path could not be selected', error)
    } finally {
      release()
    }
  }

  function changeMode(next: 'existing' | 'new') {
    if (lock.current || next === mode) return
    setMode(next)
    setWorkspace((previous) => ({ ...previous, keyFile: '' }))
    setSnapshots([])
    setSnapshotsLoaded(false)
    setVerified(false)
    setNotice(null)
  }

  async function initialize() {
    if (!pathsReady || mode !== 'new' || !acquire('initialize')) return
    try {
      await api.initialize({ repository: workspace.repository, keyFile: workspace.keyFile })
      if (!mounted.current) return
      setVerified(true)
      setMode('existing')
      setSnapshots([])
      setSnapshotsLoaded(true)
      setNotice({
        tone: 'success',
        title: 'Your local repository is ready',
        message: 'The native backend created your repository and external recovery-key file. Keep that file safe and separate; QuickSave cannot replace a lost key.',
      })
    } catch (error) {
      fail('The repository could not be created', error)
    } finally {
      release()
    }
  }

  async function loadSnapshots() {
    if (!pathsReady || mode !== 'existing' || !acquire('snapshots')) return
    try {
      const result = await api.snapshots({ repository: workspace.repository, keyFile: workspace.keyFile })
      if (!mounted.current) return
      setSnapshots(result)
      setSnapshotsLoaded(true)
      setVerified(true)
      setNotice({
        tone: 'success', title: 'Repository opened',
        message: `${result.length.toLocaleString()} saved ${result.length === 1 ? 'snapshot' : 'snapshots'} reported by the native engine.`,
      })
    } catch (error) {
      // Old results must not look like a successful current repository read.
      if (mounted.current) {
        setSnapshotsLoaded(false)
        setVerified(false)
      }
      fail('The snapshots could not be loaded', error)
    } finally {
      release()
    }
  }

  async function start(kind: Exclude<OperationKind, 'initialize'>, snapshotId?: string) {
    if (!pathsReady || mode !== 'existing') return
    if (kind === 'backup' && !workspace.source) return
    if (kind === 'restore' && (!workspace.destination || !snapshotId)) return
    if (!acquire(kind)) return
    const paths = { repository: workspace.repository, keyFile: workspace.keyFile }
    try {
      const summary = kind === 'backup'
        ? await api.backup(paths, workspace.source)
        : await api.restore(paths, snapshotId!, workspace.destination)
      let id: string
      try {
        id = operationId(summary)
      } catch (error) {
        if (mounted.current) {
          setUntrackedError(`The native request returned without a usable job identifier. It may already be running. ${safeError(error)}`)
          setBusy(null)
        }
        // A successful invoke with a malformed receipt is not permission to start another job.
        return
      }
      if (!mounted.current) return
      setTracking({
        operation: {
          id, kind, state: 'queued', startedAt: null, finishedAt: null, result: null, error: null,
        },
        paths,
        paused: null,
        recovered: false,
      })
      // The mutation lock remains held until a native terminal status is observed.
    } catch (error) {
      fail(`${kind === 'backup' ? 'Backup' : 'Restore'} could not be started`, error)
      release()
    }
  }

  const trackedId = tracking?.operation.id
  useEffect(() => {
    if (!tracking || terminal(tracking.operation.state) || tracking.paused) return
    const session = tracking
    let disposed = false
    let inFlight = false
    let requests = 0
    let errors = 0
    let stopped = false
    let interval: ReturnType<typeof setInterval> | undefined

    function stop() {
      stopped = true
      if (interval !== undefined) clearInterval(interval)
    }
    function pause(message: string) {
      stop()
      setTracking((current) => current?.operation.id === session.operation.id
        ? { ...current, paused: message } : current)
      setBusy(null)
    }
    async function poll() {
      if (disposed || stopped || inFlight) return
      if (requests >= MAX_POLL_REQUESTS) {
        pause('Automatic tracking reached its 600-request limit. The native job may still be running. Resume tracking to check it; no second operation can start yet.')
        return
      }
      inFlight = true
      requests += 1
      try {
        const operation = await api.status(session.operation.id, session.operation.kind)
        if (disposed) return
        errors = 0
        setTracking((current) => current?.operation.id === operation.id
          ? { ...current, operation, paused: null } : current)
        if (!terminal(operation.state)) return
        stop()
        if (operation.state === 'succeeded') {
          if (session.paths) setVerified(true)
          const actionName = operation.kind === 'backup' ? 'Snapshot saved' : operation.kind === 'restore' ? 'Restore completed' : 'Repository initialization completed'
          setNotice({
            tone: 'success',
            title: actionName,
            message: operation.kind === 'backup'
              ? 'The native engine reported a successful snapshot commit. Your previous versions are kept.'
              : operation.kind === 'restore' ? 'The native engine reported a successful restore to the selected empty destination.'
                : 'The native engine reported successful repository initialization. Choose the repository and external key file to open it in this session.',
          })
          if (operation.kind === 'backup' && session.paths) {
            setBusy('snapshots')
            try {
              const latest = await api.snapshots(session.paths)
              if (disposed) return
              setSnapshots(latest)
              setSnapshotsLoaded(true)
            } catch (error) {
              if (disposed) return
              setSnapshotsLoaded(false)
              setNotice({
                tone: 'info', title: 'Backup finished; snapshot list needs a refresh',
                message: `The backup succeeded, but the list could not be read: ${safeError(error)}`,
              })
            }
          }
        } else {
          setNotice({
            tone: 'error',
            title: `${operation.kind === 'backup' ? 'Backup' : operation.kind === 'restore' ? 'Restore' : 'Initialization'} ${operation.state === 'interrupted' ? 'interrupted' : 'failed'}`,
            message: operation.error || 'The native engine did not report a successful completion. No automatic retry was started.',
          })
        }
        if (!disposed) release()
      } catch (error) {
        if (disposed) return
        errors += 1
        if (errors >= MAX_STATUS_ERRORS) {
          pause(`Status tracking is paused after three unsuccessful checks. The job has not been marked failed or cancelled. ${safeError(error)}`)
        }
      } finally {
        inFlight = false
      }
    }
    interval = setInterval(() => { void poll() }, POLL_INTERVAL_MS)
    void poll()
    return () => {
      disposed = true
      stop()
    }
    // Polling belongs to a single accepted job. Status renders must not restart its timer.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [trackedId, trackingRound, release])

  function resumeTracking() {
    if (!tracking?.paused || terminal(tracking.operation.state)) return
    setTracking((previous) => previous ? { ...previous, paused: null } : previous)
    setBusy(tracking.operation.kind)
    setTrackingRound((round) => round + 1)
  }

  function retryChecks() {
    if (checking || (lock.current && !untrackedError)) return
    setChecksRound((round) => round + 1)
  }

  return {
    native, report, reportError, directories, directoriesError, historyError, checking,
    canRead, canWrite, unavailableReason, untrackedError, retryChecks,
    workspace, mode, verified, snapshots, snapshotsLoaded, busy, notice,
    operation: tracking?.operation ?? null, trackingPaused: tracking?.paused ?? null,
    operationRecovered: tracking?.recovered ?? false,
    working, pathsReady, pick, changeMode, initialize, loadSnapshots,
    backup: () => start('backup'),
    restore: (snapshotId: string) => start('restore', snapshotId),
    resumeTracking,
    dismissNotice: () => setNotice(null),
  }
}

export type QuickSave = ReturnType<typeof useQuickSave>
