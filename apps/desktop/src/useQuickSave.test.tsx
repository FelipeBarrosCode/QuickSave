import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { invoke, isTauri } from '@tauri-apps/api/core'
import { open, save } from '@tauri-apps/plugin-dialog'
import { record } from './api'
import { MAX_POLL_REQUESTS, POLL_INTERVAL_MS, useQuickSave, type QuickSave } from './useQuickSave'
import { capabilities, operation, paths, snapshot } from './test/fixtures'

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: vi.fn(() => true) }))
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: vi.fn() }))

let approvalSequence = 0
function respond(command: string): unknown {
  if (command === 'authorize_operation') return `test-native-approval-${++approvalSequence}`
  if (command === 'get_capabilities') return capabilities
  if (command === 'get_directories') return { data: '/isolated-test/data' }
  if (command === 'operation_history') return []
  if (command === 'list_snapshots') return [snapshot]
  if (command === 'backup_folder' || command === 'restore_snapshot') return operation
  if (command === 'operation_status') return operation
  if (command === 'initialize_repository') return { keySaved: true }
  throw new Error(`Unexpected test command: ${command}`)
}

beforeEach(() => {
  approvalSequence = 0
  vi.useFakeTimers()
  vi.mocked(isTauri).mockReturnValue(true)
  vi.mocked(invoke).mockImplementation(async (command) => respond(command))
  vi.mocked(open).mockReset()
  vi.mocked(save).mockReset()
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
})

async function ready() {
  const hook = renderHook(() => useQuickSave())
  await act(async () => { await Promise.resolve() })
  return hook
}

async function connect(result: { current: QuickSave }) {
  for (const field of ['repository', 'keyFile', 'source'] as const) {
    vi.mocked(open).mockResolvedValueOnce(paths[field])
    await act(async () => { await result.current.pick(field) })
  }
  await act(async () => { await result.current.loadSnapshots() })
}

describe('operation ownership and tracking', () => {
  it('keeps one pending status request and one mutation, then refreshes after native success', async () => {
    let finishStatus!: (value: unknown) => void
    let checks = 0
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === 'operation_status') {
        checks += 1
        if (checks === 1) return new Promise((resolve) => { finishStatus = resolve })
        return { ...operation, state: 'completed', result: { snapshotId: snapshot.snapshotId } }
      }
      return respond(command)
    })
    const { result } = await ready()
    await connect(result)
    await act(async () => { await result.current.backup() })
    expect(result.current.working).toBe(true)
    await act(async () => { vi.advanceTimersByTime(10 * POLL_INTERVAL_MS) })
    expect(checks).toBe(1)
    await act(async () => { await result.current.backup() })
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'backup_folder')).toHaveLength(1)
    await act(async () => { finishStatus(operation) })
    expect(result.current.operation?.state).toBe('running')
    await act(async () => { vi.advanceTimersByTime(POLL_INTERVAL_MS) })
    expect(result.current.operation?.state).toBe('succeeded')
    expect(result.current.snapshots[0].id).toBe(snapshot.snapshotId)
    expect(result.current.working).toBe(false)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('pauses after three status errors without declaring failure or unlocking a second mutation', async () => {
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === 'operation_status') throw new Error('status unavailable')
      return respond(command)
    })
    const { result } = await ready()
    await connect(result)
    await act(async () => { await result.current.backup() })
    await act(async () => { vi.advanceTimersByTime(POLL_INTERVAL_MS) })
    await act(async () => { vi.advanceTimersByTime(POLL_INTERVAL_MS) })
    expect(result.current.trackingPaused).toContain('three unsuccessful checks')
    expect(result.current.operation?.state).toBe('queued')
    expect(result.current.working).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
    await act(async () => { await result.current.backup() })
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'backup_folder')).toHaveLength(1)
    vi.mocked(invoke).mockImplementation(async (command) => command === 'operation_status'
      ? { ...operation, state: 'failed', error: 'Source changed during capture' } : respond(command))
    await act(async () => { result.current.resumeTracking() })
    expect(result.current.operation?.state).toBe('failed')
    expect(result.current.notice?.message).toContain('Source changed')
    expect(result.current.working).toBe(false)
  })

  it('bounds automatic polling while retaining ownership of a running job', async () => {
    vi.mocked(invoke).mockImplementation(async (command) =>
      command === 'operation_history' ? [operation] : respond(command))
    const { result } = await ready()
    for (let tick = 0; tick < MAX_POLL_REQUESTS; tick += 1) {
      await act(async () => { vi.advanceTimersByTime(POLL_INTERVAL_MS) })
    }
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'operation_status'))
      .toHaveLength(MAX_POLL_REQUESTS)
    expect(result.current.trackingPaused).toContain('600-request limit')
    expect(result.current.operation?.state).toBe('running')
    expect(result.current.working).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('clears the interval on unmount and ignores a late native completion', async () => {
    let finishStatus!: (value: unknown) => void
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === 'operation_history') return [operation]
      if (command === 'operation_status') return new Promise((resolve) => { finishStatus = resolve })
      return respond(command)
    })
    const { unmount } = await ready()
    expect(vi.getTimerCount()).toBe(1)
    unmount()
    expect(vi.getTimerCount()).toBe(0)
    await act(async () => {
      finishStatus({ ...operation, state: 'completed' })
      vi.advanceTimersByTime(10 * POLL_INTERVAL_MS)
    })
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'operation_status')).toHaveLength(1)
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'list_snapshots')).toHaveLength(0)
  })

  it('recovers an interrupted receipt without retrying it or verifying a repository', async () => {
    vi.mocked(invoke).mockImplementation(async (command) => command === 'operation_history'
      ? [{ ...operation, state: 'interrupted', error: 'Previous process ended; inspect before retrying.' }]
      : respond(command))
    const { result } = await ready()
    expect(result.current.operation?.state).toBe('interrupted')
    expect(result.current.operationRecovered).toBe(true)
    expect(result.current.verified).toBe(false)
    expect(result.current.working).toBe(false)
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'backup_folder')).toHaveLength(0)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('holds the mutation lock when a successful submission has no job identifier', async () => {
    vi.mocked(invoke).mockImplementation(async (command) => command === 'backup_folder' ? {} : respond(command))
    const { result } = await ready()
    await connect(result)
    await act(async () => { await result.current.backup() })
    expect(result.current.untrackedError).toContain('may already be running')
    expect(result.current.working).toBe(true)
    await act(async () => { await result.current.backup() })
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'backup_folder')).toHaveLength(1)
    await act(async () => { result.current.retryChecks() })
    expect(result.current.untrackedError).toBeNull()
    expect(result.current.working).toBe(false)
  })
})

describe('native setup and explicit failure', () => {
  it('creates a repository with a native save path and then enters existing-repository mode', async () => {
    const { result } = await ready()
    act(() => result.current.changeMode('new'))
    vi.mocked(open).mockResolvedValueOnce(paths.repository)
    await act(async () => { await result.current.pick('repository') })
    vi.mocked(save).mockResolvedValueOnce(paths.keyFile)
    await act(async () => { await result.current.pick('keyFile') })
    await act(async () => { await result.current.initialize() })
    expect(invoke).toHaveBeenCalledWith('initialize_repository', {
      repository: paths.repository, keyFile: paths.keyFile, approvalId: 'test-native-approval-1',
    })
    expect(result.current.mode).toBe('existing')
    expect(result.current.verified).toBe(true)
    expect(result.current.snapshotsLoaded).toBe(true)
  })

  it('disables mutations if native history cannot be read, and allows an explicit recheck', async () => {
    let unavailable = true
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === 'operation_history' && unavailable) throw new Error('Cannot read private history')
      return respond(command)
    })
    const { result } = await ready()
    expect(result.current.canWrite).toBe(false)
    expect(result.current.canRead).toBe(true)
    expect(result.current.historyError).toContain('Cannot read')
    unavailable = false
    await act(async () => { result.current.retryChecks() })
    expect(result.current.canWrite).toBe(true)
  })

  it('exposes command errors without marking a failed list as verified or loaded', async () => {
    const { result } = await ready()
    await connect(result)
    vi.mocked(invoke).mockRejectedValueOnce(new Error('<b>Wrong recovery key</b>'))
    await act(async () => { await result.current.loadSnapshots() })
    expect(result.current.notice?.tone).toBe('error')
    expect(result.current.notice?.message).toBe('<b>Wrong recovery key</b>')
    expect(result.current.snapshotsLoaded).toBe(false)
    expect(result.current.verified).toBe(false)
  })

  it('never reuses an old successful capability report after a failed recheck', async () => {
    const { result } = await ready()
    expect(result.current.canWrite).toBe(true)
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === 'get_capabilities') throw new Error('Native capability service unavailable')
      return respond(command)
    })
    await act(async () => { result.current.retryChecks() })
    expect(result.current.canWrite).toBe(false)
    expect(result.current.canRead).toBe(false)
    expect(result.current.report).toBeNull()
    expect(result.current.reportError).toContain('unavailable')
  })

  it('blocks scope changes and a second mutation while native backup consent is pending', async () => {
    const { result } = await ready()
    await connect(result)
    let cancel!: (error: Error) => void
    vi.mocked(invoke).mockImplementationOnce(() => new Promise((_resolve, reject) => { cancel = reject }))
    let submission!: Promise<void>
    await act(async () => { submission = result.current.backup() })
    expect(result.current.working).toBe(true)
    expect(result.current.operation).toBeNull()
    const pickerCalls = vi.mocked(open).mock.calls.length
    await act(async () => {
      await result.current.pick('source')
      await result.current.backup()
      result.current.changeMode('new')
    })
    expect(open).toHaveBeenCalledTimes(pickerCalls)
    expect(result.current.mode).toBe('existing')
    expect(result.current.workspace.source).toBe(paths.source)
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'backup_folder')).toHaveLength(0)
    await act(async () => {
      cancel(new Error('Native confirmation cancelled'))
      await submission
    })
    expect(result.current.working).toBe(false)
    expect(result.current.operation).toBeNull()
    expect(result.current.notice?.message).toBe('Native confirmation cancelled')
  })

  it('keeps successful backup state when fresh native consent for automatic history refresh is cancelled', async () => {
    let listApprovals = 0
    let cancelRefresh!: (error: Error) => void
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (command === 'authorize_operation' && record(args)?.kind === 'list') {
        listApprovals += 1
        if (listApprovals === 2) return new Promise((_resolve, reject) => { cancelRefresh = reject })
      }
      if (command === 'operation_status') return { ...operation, state: 'completed' }
      return respond(command)
    })
    const { result } = await ready()
    await connect(result)
    await act(async () => { await result.current.backup() })
    expect(result.current.operation?.state).toBe('succeeded')
    expect(result.current.busy).toBe('snapshots')
    expect(result.current.working).toBe(true)
    expect(listApprovals).toBe(2)
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'list_snapshots')).toHaveLength(1)
    await act(async () => { cancelRefresh(new Error('Native refresh approval cancelled')) })
    expect(result.current.operation?.state).toBe('succeeded')
    expect(result.current.notice?.tone).toBe('info')
    expect(result.current.notice?.title).toBe('Backup finished; snapshot list needs a refresh')
    expect(result.current.working).toBe(false)
    expect(result.current.snapshotsLoaded).toBe(false)
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'list_snapshots')).toHaveLength(1)
    await act(async () => { await result.current.loadSnapshots() })
    expect(listApprovals).toBe(3)
    expect(result.current.snapshotsLoaded).toBe(true)
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'list_snapshots')).toHaveLength(2)
  })
})
