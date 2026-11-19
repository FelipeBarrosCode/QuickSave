import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { invoke, isTauri } from '@tauri-apps/api/core'
import { MAX_POLL_REQUESTS, POLL_INTERVAL_MS, useQuickSave } from './useQuickSave'
import { record } from './api'
import { activity, appTracking, dashboard, provider, respond } from './test/fixtures'

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: vi.fn(() => true) }))
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: vi.fn() }))

beforeEach(() => {
  vi.useFakeTimers()
  vi.mocked(isTauri).mockReturnValue(true)
  vi.mocked(invoke).mockImplementation(async (command, args) => respond(command, args as Record<string, unknown>))
})
afterEach(() => { cleanup(); vi.useRealTimers() })
async function ready() {
  const hook = renderHook(useQuickSave)
  await act(async () => { await Promise.resolve() })
  return hook
}
async function tick() { await act(async () => { await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS) }) }

describe('bounded activity polling', () => {
  it('does not queue tracking or activity reads while startup waits for Keychain consent', async () => {
    let finish!: (value: unknown) => void
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (record(args)?.query === 'dashboard') return new Promise((resolve) => { finish = resolve })
      return respond(command, args as Record<string, unknown>)
    })
    const { result } = await ready()
    await act(async () => { await vi.advanceTimersByTimeAsync(30 * POLL_INTERVAL_MS) })
    expect(result.current.loading).toBe(true)
    expect(vi.mocked(invoke).mock.calls.map(([, args]) => record(args)?.query)).toEqual(['dashboard'])
    expect(result.current.pollIssue).toBeNull()
    await act(async () => { finish(dashboard) })
    expect(result.current.loading).toBe(false)
    expect(vi.mocked(invoke).mock.calls.filter(([, args]) => record(args)?.query === 'app_tracking')).toHaveLength(1)
    await tick()
    expect(vi.mocked(invoke).mock.calls.filter(([, args]) => record(args)?.query === 'activity')).toHaveLength(1)
  })

  it('keeps background reads paused when startup authorization fails', async () => {
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (record(args)?.query === 'dashboard') throw new Error('Native vault access denied')
      return respond(command, args as Record<string, unknown>)
    })
    const { result } = await ready()
    await act(async () => { await vi.advanceTimersByTimeAsync(30 * POLL_INTERVAL_MS) })
    expect(result.current.error).toBeTruthy()
    expect(vi.mocked(invoke).mock.calls.map(([, args]) => record(args)?.query)).toEqual(['dashboard'])
    expect(result.current.pollIssue).toBeNull()
  })

  it('polls every two seconds and never overlaps a slow request', async () => {
    let finish!: (value: unknown) => void
    let count = 0
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (record(args)?.query === 'activity') {
        count += 1
        return new Promise((resolve) => { finish = resolve })
      }
      return respond(command, args as Record<string, unknown>)
    })
    const { result } = await ready()
    await tick()
    await act(async () => { await vi.advanceTimersByTimeAsync(10 * POLL_INTERVAL_MS) })
    expect(count).toBe(1)
    await act(async () => { finish({ activity: [activity] }) })
    expect(result.current.activity[0].state).toBe('running')
    await tick()
    expect(count).toBe(2)
  })
  it('pauses after three errors without inventing cancelled or completed state', async () => {
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (record(args)?.query === 'activity') throw new Error('offline-test')
      if (record(args)?.query === 'dashboard') return { ...dashboard, activity: [activity] }
      return respond(command, args as Record<string, unknown>)
    })
    const { result } = await ready()
    await tick(); await tick(); await tick()
    expect(result.current.pollIssue).toContain('three checks')
    expect(result.current.activity[0].state).toBe('running')
    expect(vi.getTimerCount()).toBe(0)
    act(() => result.current.resumePolling())
    await tick()
    expect(vi.mocked(invoke).mock.calls.filter(([, args]) => record(args)?.query === 'activity')).toHaveLength(4)
  })
  it('has a 600-request cap and requires explicit resumption', async () => {
    vi.mocked(invoke).mockImplementation(async (command, args) =>
      record(args)?.query === 'activity' ? { activity: [activity] }
        : respond(command, args as Record<string, unknown>))
    const { result } = await ready()
    for (let index = 0; index <= MAX_POLL_REQUESTS; index += 1) await tick()
    expect(vi.mocked(invoke).mock.calls.filter(([, args]) => record(args)?.query === 'activity')).toHaveLength(MAX_POLL_REQUESTS)
    expect(result.current.pollIssue).toContain('600')
    expect(vi.getTimerCount()).toBe(0)
  })
  it('does not exhaust an activity budget while the workspace is idle', async () => {
    const { result } = await ready()
    for (let index = 0; index <= MAX_POLL_REQUESTS; index += 1) await tick()
    expect(vi.mocked(invoke).mock.calls.filter(([, args]) => record(args)?.query === 'activity')).toHaveLength(1)
    expect(result.current.pollIssue).toBeNull()
    expect(vi.getTimerCount()).toBe(0)
    expect(vi.mocked(invoke).mock.calls.some(([command]) => command === 'workspace_execute')).toBe(false)
  })
  it('resumes bounded status checks after an accepted user action in an idle workspace', async () => {
    const { result } = await ready()
    await tick()
    expect(vi.getTimerCount()).toBe(0)
    await act(async () => { await result.current.run('refresh_app_tracking', {}) })
    await tick()
    expect(vi.mocked(invoke).mock.calls.filter(([, args]) => record(args)?.query === 'activity')).toHaveLength(2)
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'workspace_execute')).toHaveLength(1)
    expect(result.current.pollIssue).toBeNull()
    expect(vi.getTimerCount()).toBe(0)
  })
  it('shares an in-flight activity request when a user resumes checks', async () => {
    let finish!: (value: unknown) => void
    let count = 0
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (record(args)?.query === 'activity') {
        count += 1
        if (count === 1) return new Promise((resolve) => { finish = resolve })
        return { activity: [activity] }
      }
      return respond(command, args as Record<string, unknown>)
    })
    const { result } = await ready()
    await tick()
    act(() => result.current.resumePolling())
    await tick(); await tick()
    expect(count).toBe(1)
    await act(async () => { finish({ activity: [activity] }) })
    expect(result.current.activity[0].state).toBe('running')
    await tick()
    expect(count).toBe(2)
    expect(vi.mocked(invoke).mock.calls.some(([command]) => command === 'workspace_execute')).toBe(false)
  })
  it('retains missing unfinished work instead of treating absence as completion', async () => {
    vi.mocked(invoke).mockImplementation(async (command, args) =>
      record(args)?.query === 'dashboard' ? { ...dashboard, activity: [activity] }
        : respond(command, args as Record<string, unknown>))
    const { result } = await ready()
    await tick(); await tick()
    expect(result.current.activity).toHaveLength(1)
    expect(result.current.activity[0]).toMatchObject(activity)
    expect(result.current.pollIssue).toContain('last known state')
    expect(vi.getTimerCount()).toBe(0)
    expect(vi.mocked(invoke).mock.calls.filter(([, args]) => record(args)?.query === 'activity')).toHaveLength(1)
  })
  it('keeps unfinished known work when a full native page would otherwise evict it', async () => {
    vi.mocked(invoke).mockImplementation(async (command, args) =>
      record(args)?.query === 'dashboard' ? { ...dashboard, activity: [activity] }
        : record(args)?.query === 'activity' ? {
          activity: Array.from({ length: 128 }, (_, index) => ({ ...activity, id: `later-operation-${index}` })),
        } : respond(command, args as Record<string, unknown>))
    const { result } = await ready()
    await tick(); await tick()
    expect(result.current.activity).toHaveLength(128)
    expect(result.current.activity[0]).toMatchObject(activity)
    expect(result.current.pollIssue).toContain('128 rows')
    expect(vi.getTimerCount()).toBe(0)
  })
  it('refreshes software state only after native completion', async () => {
    let completed = false
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (record(args)?.query === 'activity') return { activity: [{ ...activity, state: completed ? 'completed' : 'running' }] }
      if (record(args)?.query === 'dashboard') return { ...dashboard, software: [
        { ...dashboard.software[0], status: completed ? 'saved' : 'needs_backup' },
      ] }
      return respond(command, args as Record<string, unknown>)
    })
    const { result } = await ready()
    await tick()
    expect(result.current.dashboard?.software[0].status).toBe('needs_backup')
    completed = true
    await tick()
    expect(result.current.dashboard?.software[0].status).toBe('saved')
  })
  it('cancels future timers and ignores an activity response after unmount', async () => {
    let finish!: (value: unknown) => void
    vi.mocked(invoke).mockImplementation(async (command, args) => record(args)?.query === 'activity'
      ? new Promise((resolve) => { finish = resolve }) : respond(command, args as Record<string, unknown>))
    const { unmount } = await ready()
    await tick()
    unmount()
    await act(async () => { finish({ activity: [activity] }) })
    expect(vi.getTimerCount()).toBe(0)
  })
})

describe('native state remains authoritative', () => {
  it('treats local restore recovery as a rollback report, never a completed replacement download operation', async () => {
    const interrupted = { ...activity, id: 'original-interrupted-restore', kind: 'download', state: 'interrupted', canRecover: true }
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (command === 'workspace_execute') return { recovery: { retained: 1, recovered: true } }
      if (record(args)?.query === 'dashboard') return { ...dashboard, activity: [interrupted] }
      return respond(command, args as Record<string, unknown>)
    })
    const { result } = await ready()
    await act(async () => { await result.current.run('recover_restore', { operationId: interrupted.id }) })
    expect(result.current.activity[0].id).toBe(interrupted.id)
    expect(result.current.activity[0].state).toBe('interrupted')
    expect(vi.mocked(invoke).mock.calls.some(([, args]) => record(args)?.query === 'operation')).toBe(false)
  })
  it('reattaches native-reported batch identities after startup without rebuilding a plan or polling large catalogs', async () => {
    const group = { ...activity, id: 'native-batch-operation', planSetId: 'native-batch-plan' }
    vi.mocked(invoke).mockImplementation(async (command, args) =>
      record(args)?.query === 'dashboard' ? { ...dashboard, activity: [group] }
        : respond(command, args as Record<string, unknown>))
    const { result } = await ready()
    expect(result.current.batches).toEqual([{ operationId: group.id, planSetId: group.planSetId, providerId: provider.id }])
    await tick(); await tick()
    expect(vi.mocked(invoke).mock.calls.some(([command]) => command === 'workspace_prepare')).toBe(false)
    expect(vi.mocked(invoke).mock.calls.some(([, args]) =>
      ['bundles', 'history', 'catalog_apps', 'pending_deletions', 'software_files'].includes(String(record(args)?.query)))).toBe(false)
  })
  it('does not optimistically enable autosave when consent or network fails', async () => {
    const { result } = await ready()
    vi.mocked(invoke).mockRejectedValueOnce(new Error('native grant denied'))
    await act(async () => { await result.current.run('set_autosave', {
      softwareId: 'software-test', providerId: provider.id, enabled: true,
    }) })
    expect(result.current.dashboard?.software[0].autosave).toBe(false)
    expect(result.current.notice).toContain('denied')
  })
  it('serializes preparations and never repeats an execution after a failure', async () => {
    let finish!: (value: unknown) => void
    const { result } = await ready()
    vi.mocked(invoke).mockImplementation(async (command, args) => command === 'workspace_prepare'
      ? new Promise((resolve) => { finish = resolve }) : respond(command, args as Record<string, unknown>))
    let first!: Promise<unknown>
    act(() => { first = result.current.run('upload', { softwareId: 'software-test', providerId: provider.id }) })
    await act(async () => { await result.current.run('upload', { softwareId: 'software-test', providerId: provider.id }) })
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'workspace_prepare')).toHaveLength(1)
    await act(async () => { finish({ ticketId: 'test-ticket' }); await first })
    expect(result.current.busy).toBeNull()
  })
  it('fails closed when workspace metadata cannot be read', async () => {
    vi.mocked(invoke).mockRejectedValueOnce(new Error('workspace unavailable'))
    const { result } = await ready()
    expect(result.current.ready).toBe(false)
    await act(async () => { await result.current.run('upload', { softwareId: 'test', providerId: provider.id }) })
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'workspace_prepare')).toHaveLength(0)
  })
  it('abandons pending consent on unmount without executing a late ticket or cancelling running work', async () => {
    const { result, unmount } = await ready()
    let finish!: (value: unknown) => void
    vi.mocked(invoke).mockImplementationOnce(() => new Promise((resolve) => { finish = resolve }))
    let request!: Promise<unknown>
    act(() => { request = result.current.run('upload', { softwareId: 'software-test', providerId: provider.id }) })
    unmount()
    await act(async () => { finish({ ticketId: 'late-ticket' }); await request })
    expect(vi.mocked(invoke).mock.calls.filter(([command]) => command === 'workspace_execute')).toHaveLength(0)
    expect(vi.mocked(invoke).mock.calls.filter(([, args]) => record(args)?.action === 'cancel')).toHaveLength(0)
  })
})

describe('finite native app-tracking checks', () => {
  it('does not poll an idle scan or manufacture clock-based app progress', async () => {
    const { result } = await ready()
    await tick(); await tick()
    expect(result.current.tracking).toEqual(appTracking)
    expect(vi.mocked(invoke).mock.calls.filter(([, args]) => record(args)?.query === 'app_tracking')).toHaveLength(1)
  })
  it('serializes slow tracking checks and shares an in-flight request with manual status refresh', async () => {
    let finish!: (value: unknown) => void
    let requests = 0
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (record(args)?.query === 'app_tracking') {
        requests += 1
        if (requests === 1) return { ...appTracking, scanning: true, completedApps: 0, totalApps: 2 }
        return new Promise((resolve) => { finish = resolve })
      }
      return respond(command, args as Record<string, unknown>)
    })
    const { result } = await ready()
    await tick()
    act(() => { void result.current.refreshTracking() })
    await act(async () => { await vi.advanceTimersByTimeAsync(10 * POLL_INTERVAL_MS) })
    expect(requests).toBe(2)
    expect(result.current.tracking?.completedApps).toBe(0)
    await act(async () => { finish({ ...appTracking, scanning: true, completedApps: 1, totalApps: 2 }) })
    expect(result.current.tracking?.completedApps).toBe(1)
    await tick()
    expect(requests).toBe(3)
  })
  it('refreshes actual local inventory and stops scan polling only when native scanning finishes', async () => {
    let scanning = true
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (record(args)?.query === 'app_tracking') return {
        ...appTracking, scanning, completedApps: scanning ? 0 : 1,
      }
      if (record(args)?.query === 'dashboard') return { ...dashboard, software: scanning ? [] : dashboard.software }
      return respond(command, args as Record<string, unknown>)
    })
    const { result } = await ready()
    expect(result.current.dashboard?.software).toEqual([])
    await tick()
    expect(result.current.tracking?.completedApps).toBe(0)
    scanning = false
    await tick()
    expect(result.current.tracking?.scanning).toBe(false)
    expect(result.current.dashboard?.software).toEqual(dashboard.software)
    const requests = vi.mocked(invoke).mock.calls.filter(([, args]) => record(args)?.query === 'app_tracking').length
    await tick(); await tick()
    expect(vi.mocked(invoke).mock.calls.filter(([, args]) => record(args)?.query === 'app_tracking')).toHaveLength(requests)
  })
  it('pauses scan checks after three failures without calling an unfinished scan complete', async () => {
    let requests = 0
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (record(args)?.query === 'app_tracking') {
        requests += 1
        if (requests === 1) return { ...appTracking, scanning: true, completedApps: 0 }
        throw new Error('isolated scan status unavailable')
      }
      return respond(command, args as Record<string, unknown>)
    })
    const { result } = await ready()
    await tick(); await tick(); await tick()
    expect(result.current.trackingPollIssue).toContain('three checks')
    expect(result.current.tracking?.scanning).toBe(true)
    expect(result.current.tracking?.completedApps).toBe(0)
    await tick(); await tick()
    expect(requests).toBe(4)
    act(() => result.current.resumeTrackingPolling())
    await act(async () => { await Promise.resolve() })
    expect(requests).toBe(5)
  })
  it('bounds a native scan to 600 serial polling requests and requires explicit resumption', async () => {
    vi.mocked(invoke).mockImplementation(async (command, args) => record(args)?.query === 'app_tracking'
      ? { ...appTracking, scanning: true, completedApps: 0 }
      : respond(command, args as Record<string, unknown>))
    const { result } = await ready()
    for (let index = 0; index <= MAX_POLL_REQUESTS; index += 1) await tick()
    expect(vi.mocked(invoke).mock.calls.filter(([, args]) => record(args)?.query === 'app_tracking')).toHaveLength(MAX_POLL_REQUESTS + 1)
    expect(result.current.trackingPollIssue).toContain('600')
    expect(result.current.tracking?.scanning).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })
  it('does not pretend tracking is disabled when the native tracking query is unsupported', async () => {
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (record(args)?.query === 'app_tracking') throw new Error('App tracking is unsupported')
      return respond(command, args as Record<string, unknown>)
    })
    const { result } = await ready()
    expect(result.current.ready).toBe(true)
    expect(result.current.tracking).toBeNull()
    expect(result.current.trackingError).toBe('App tracking is unsupported')
    expect(result.current.dashboard?.software).toEqual(dashboard.software)
  })
  it('cancels future scan timers on unmount without cancelling native scanning or accepting a late response', async () => {
    let finish!: (value: unknown) => void
    let requests = 0
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (record(args)?.query === 'app_tracking') {
        requests += 1
        if (requests === 1) return { ...appTracking, scanning: true, completedApps: 0 }
        return new Promise((resolve) => { finish = resolve })
      }
      return respond(command, args as Record<string, unknown>)
    })
    const { unmount } = await ready()
    await tick()
    unmount()
    await act(async () => { finish(appTracking) })
    expect(vi.getTimerCount()).toBe(0)
    expect(vi.mocked(invoke).mock.calls.some(([command]) => command === 'workspace_prepare')).toBe(false)
  })
})
