import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { invoke, isTauri } from '@tauri-apps/api/core'
import { useBatchStatus } from './BatchUpload'
import { record } from './api'
import { MAX_POLL_REQUESTS, POLL_INTERVAL_MS } from './useQuickSave'
import { batchPreview, batchResponse, batchStatus } from './test/fixtures'

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: vi.fn(() => true) }))
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: vi.fn() }))
const reference = { planSetId: batchPreview.planSetId, operationId: batchStatus.operationId }
beforeEach(() => {
  vi.useFakeTimers()
  vi.mocked(isTauri).mockReturnValue(true)
  vi.mocked(invoke).mockImplementation(async () => batchResponse())
})
afterEach(() => { cleanup(); vi.useRealTimers() })
async function ready() {
  const hook = renderHook(() => useBatchStatus(reference))
  await act(async () => { await Promise.resolve() })
  return hook
}
async function tick() { await act(async () => { await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS) }) }

describe('finite actual batch status checks', () => {
  it('queries only the native frozen plan ID and preserves actual job counts without catalog walks or progress estimates', async () => {
    const { result } = await ready()
    expect(result.current.status?.childCount).toBe(1)
    expect(result.current.status?.progress[0].total).toBeUndefined()
    await tick()
    expect(vi.mocked(invoke).mock.calls).toHaveLength(2)
    expect(vi.mocked(invoke).mock.calls.every(([command, args]) => command === 'workspace_query'
      && record(args)?.query === 'batch_status')).toBe(true)
    expect(invoke).toHaveBeenCalledWith('workspace_query', { query: 'batch_status', params: { planSetId: batchPreview.planSetId } })
  })
  it('keeps initial batch:null counts unknown rather than pretending zero apps or completed work', async () => {
    vi.mocked(invoke).mockResolvedValue({ ...batchResponse(), state: 'queued', batch: null })
    const { result } = await ready()
    expect(result.current.status?.state).toBe('queued')
    expect(result.current.status?.childCount).toBeUndefined()
    expect(result.current.status?.completed).toBeUndefined()
    expect(result.current.status?.shutdownBlocked).toBeUndefined()
    await tick()
    expect(invoke).toHaveBeenCalledTimes(2)
  })
  it('serializes slow requests and shares an in-flight status check with manual refresh', async () => {
    let finish!: (value: unknown) => void
    vi.mocked(invoke).mockImplementation(() => new Promise((resolve) => { finish = resolve }))
    const { result } = await ready()
    act(() => result.current.refresh())
    await act(async () => { await vi.advanceTimersByTimeAsync(10 * POLL_INTERVAL_MS) })
    expect(invoke).toHaveBeenCalledTimes(1)
    expect(result.current.status).toBeNull()
    await act(async () => { finish(batchResponse()) })
    expect(result.current.status?.state).toBe('running')
    await tick()
    expect(invoke).toHaveBeenCalledTimes(2)
  })
  it('pauses after three failures without marking work cancelled or retrying native execution', async () => {
    const { result } = await ready()
    vi.mocked(invoke).mockRejectedValue(new Error('Native source status unavailable'))
    await tick(); await tick(); await tick()
    expect(result.current.issue).toContain('Native work may still be running')
    expect(result.current.status?.state).toBe('running')
    expect(vi.getTimerCount()).toBe(0)
    vi.mocked(invoke).mockResolvedValue(batchResponse())
    act(() => result.current.refresh())
    await act(async () => { await Promise.resolve() })
    expect(result.current.issue).toBeNull()
    expect(vi.mocked(invoke).mock.calls.every(([command]) => command === 'workspace_query')).toBe(true)
  })
  it('has a 600-request cap with explicit resumption, not automatic operation retry', async () => {
    const { result } = await ready()
    for (let index = 0; index < MAX_POLL_REQUESTS; index += 1) await tick()
    expect(invoke).toHaveBeenCalledTimes(MAX_POLL_REQUESTS)
    expect(result.current.issue).toContain('600')
    expect(vi.getTimerCount()).toBe(0)
  })
  it('continues checking terminal-looking work until native workers are drained, then stops', async () => {
    vi.mocked(invoke).mockResolvedValue(batchResponse({ ...batchStatus, state: 'completed', shutdownBlocked: true }))
    const { result } = await ready()
    await tick()
    expect(invoke).toHaveBeenCalledTimes(2)
    vi.mocked(invoke).mockResolvedValue(batchResponse({ ...batchStatus, state: 'completed', shutdownBlocked: false, completed: 1, active: 0 }))
    await tick()
    expect(result.current.status?.shutdownBlocked).toBe(false)
    expect(result.current.status?.completed).toBe(1)
    expect(vi.getTimerCount()).toBe(0)
  })
  it('clears timers and abandons late status responses on unmount without cancelling native jobs', async () => {
    let finish!: (value: unknown) => void
    vi.mocked(invoke).mockImplementation(() => new Promise((resolve) => { finish = resolve }))
    const { unmount } = await ready()
    unmount()
    await act(async () => { finish(batchResponse()) })
    expect(vi.getTimerCount()).toBe(0)
    expect(invoke).toHaveBeenCalledTimes(1)
  })
})
