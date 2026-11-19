// SPDX-License-Identifier: GPL-3.0-only
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { invoke, isTauri } from '@tauri-apps/api/core'
import App from './App'
import { api, normalizeVaultStatus, record } from './api'
import { respond, type Call } from './test/fixtures'

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: vi.fn(() => true) }))
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: vi.fn() }))
const legacy = { format: 'legacy', secretsInPlaintext: false, nativeAuthorizationVerified: false }
const encrypted = { ...legacy, format: 'encrypted_state' }
let calls: Call[]
let current: unknown
let prepareError: string | null
let executeError: string | null
let storageReady: boolean
beforeEach(() => {
  calls = []
  current = legacy
  prepareError = null
  executeError = null
  storageReady = true
  vi.mocked(isTauri).mockReturnValue(true)
  vi.mocked(invoke).mockImplementation(async (command, args) => {
    calls.push({ command, args: structuredClone(args ?? {}) as Record<string, unknown> })
    if (record(args)?.query === 'vault_status') return current
    if (record(args)?.query === 'vault_readiness') return { ready: storageReady }
    if (command === 'workspace_prepare') {
      if (prepareError) throw new Error(prepareError)
      return { ticketId: 'native-migration-ticket' }
    }
    if (command === 'workspace_execute') {
      if (executeError) throw new Error(executeError)
      current = encrypted
      return { format: 'encrypted_state', legacyItemsDeleted: false }
    }
    return respond(command, args as Record<string, unknown>)
  })
})
afterEach(() => { cleanup(); vi.useRealTimers() })
const queryNames = () => calls.filter((call) => call.command === 'workspace_query').map((call) => call.args.query)
const preparations = () => calls.filter((call) => call.command === 'workspace_prepare')
const executions = () => calls.filter((call) => call.command === 'workspace_execute')

describe('explicit pre-worker vault migration', () => {
  it('leaves legacy startup paused for 60 seconds with no dashboard, tracking, activity or consent calls', async () => {
    vi.useFakeTimers()
    render(<App />)
    await act(async () => { await Promise.resolve() })
    expect(screen.getByRole('button', { name: 'Start local tracking' })).toBeTruthy()
    await act(async () => { vi.advanceTimersByTime(60_000) })
    expect(queryNames()).toEqual(['vault_status'])
    expect(preparations()).toEqual([])
    expect(executions()).toEqual([])
    expect(screen.queryByText('Desktop')).toBeNull()
  })

  it('requests exact native approval only on click, spends only the ticket and rechecks format before mounting', async () => {
    render(<App />)
    fireEvent.click(await screen.findByRole('button', { name: 'Start local tracking' }))
    await screen.findByText('Desktop')
    expect(preparations()).toEqual([{
      command: 'workspace_prepare', args: { action: 'setup_local_tracking', params: {} },
    }])
    expect(executions()).toEqual([{
      command: 'workspace_execute', args: { ticketId: 'native-migration-ticket' },
    }])
    expect(queryNames().slice(0, 3)).toEqual(['vault_status', 'vault_status', 'vault_readiness'])
    expect(queryNames()).toContain('dashboard')
  })

  it('native cancellation never executes or starts workspace workers', async () => {
    prepareError = 'Native authorization canceled; no new access was granted'
    render(<App />)
    fireEvent.click(await screen.findByRole('button', { name: 'Start local tracking' }))
    await screen.findByRole('alert')
    expect(screen.getByRole('alert').textContent).toContain('not confirmed complete')
    expect(executions()).toEqual([])
    expect(queryNames()).toEqual(['vault_status'])
    expect(screen.queryByText('Desktop')).toBeNull()
    expect(screen.getByRole('button', { name: 'Continue without setup' })).toBeTruthy()
  })

  it('unreadable legacy items report failure without claims of success, resets, deletion or automatic retry', async () => {
    executeError = 'Native access to every legacy QuickSave item is required.'
    render(<App />)
    fireEvent.click(await screen.findByRole('button', { name: 'Start local tracking' }))
    await screen.findByRole('alert')
    expect(screen.getByRole('alert').textContent).toContain('Old credential values are retained; no old item is deleted')
    expect(current).toEqual(legacy)
    expect(preparations()).toHaveLength(1)
    expect(executions()).toHaveLength(1)
    expect(queryNames()).toEqual(['vault_status'])
    expect(screen.queryByText('Desktop')).toBeNull()
    expect(screen.getByRole('button', { name: 'Start local tracking' }).hasAttribute('disabled')).toBe(false)
  })

  it('does not mount after an execution response if fresh metadata still reports legacy', async () => {
    const original = vi.mocked(invoke).getMockImplementation()!
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (command === 'workspace_execute') return { format: 'encrypted_state' }
      return original(command, args)
    })
    render(<App />)
    fireEvent.click(await screen.findByRole('button', { name: 'Start local tracking' }))
    await screen.findByRole('alert')
    expect(queryNames()).toEqual(['vault_status', 'vault_status'])
    expect(screen.queryByText('Desktop')).toBeNull()
  })

  it('continuing without migration is an explicit choice and never requests migration consent', async () => {
    render(<App />)
    fireEvent.click(await screen.findByRole('button', { name: 'Continue without setup' }))
    await screen.findByText('Desktop')
    expect(preparations()).toEqual([])
    expect(queryNames()).toContain('dashboard')
  })

  it('encrypted format mounts normally without asking for migration or claiming native authorization', async () => {
    current = encrypted
    render(<App />)
    await screen.findByText('Desktop')
    expect(preparations()).toEqual([])
    expect(executions()).toEqual([])
    expect(queryNames()[0]).toBe('vault_status')
  })

  it('shows native inventory limitations and disables unsupported migration without starting workers', async () => {
    current = { ...legacy, legacyInventorySupported: false,
      legacyMigrationLimitation: 'Bounded service-confined Windows legacy inventory is not supported.' }
    render(<App />)
    const button = await screen.findByRole('button', { name: 'Start local tracking' })
    expect(button.hasAttribute('disabled')).toBe(true)
    expect(screen.getByText('Bounded service-confined Windows legacy inventory is not supported.')).toBeTruthy()
    fireEvent.click(button)
    expect(preparations()).toEqual([])
    expect(queryNames()).toEqual(['vault_status'])
  })

  it('browser preview never makes native calls', async () => {
    vi.mocked(isTauri).mockReturnValue(false)
    render(<App />)
    await waitFor(() => expect(screen.getByText('Browser preview')).toBeTruthy())
    expect(calls).toEqual([])
  })

  it('a broken metadata response keeps startup paused and offers a local-only retry', async () => {
    current = { format: 'encrypted_state', nativeAuthorizationVerified: true }
    render(<App />)
    await screen.findByRole('alert')
    expect(screen.getByRole('button', { name: 'Retry local format check' })).toBeTruthy()
    expect(queryNames()).toEqual(['vault_status'])
    expect(screen.queryByText('Desktop')).toBeNull()
  })

  it('exposes only format/support metadata, never authority or secret payload fields', async () => {
    current = { ...encrypted, encryptedSecrets: 'not-for-webview-model', generation: 9, workspaceIdentity: 'not-authority' }
    expect(await api.vaultStatus()).toEqual(encrypted)
    expect(normalizeVaultStatus(current)).not.toHaveProperty('encryptedSecrets')
    expect(normalizeVaultStatus(current)).not.toHaveProperty('workspaceIdentity')
    expect(() => normalizeVaultStatus({ ...encrypted, nativeAuthorizationVerified: true })).toThrow()
  })

  it('rejects every caller-supplied migration parameter before native IPC', async () => {
    for (const action of ['migrate_vault', 'setup_local_tracking', 'authorize_tracking_storage'] as const) {
      await expect(api.action(action, { generation: 1 } as never)).rejects.toThrow('no caller-supplied')
    }
    expect(calls).toEqual([])
  })

  it('allows ready encrypted pending storage to continue without bulk import', async () => {
    current = { ...encrypted, credentialSetupPending: true }
    render(<App />)
    await screen.findByText('Local tracking is ready')
    expect(queryNames()).toEqual(['vault_status', 'vault_readiness'])
    expect(preparations()).toEqual([])
    fireEvent.click(screen.getByRole('button', { name: 'Continue local tracking' }))
    await screen.findByText('Desktop')
    expect(preparations()).toEqual([])
  })

  it('enters the workspace immediately after local setup even when credential import remains pending', async () => {
    const original = vi.mocked(invoke).getMockImplementation()!
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      const result = await original(command, args)
      if (command === 'workspace_execute') current = { ...encrypted, credentialSetupPending: true }
      return result
    })
    render(<App />)
    fireEvent.click(await screen.findByRole('button', { name: 'Start local tracking' }))
    await screen.findByText('Desktop')
    expect(preparations().map((call) => call.args.action)).toEqual(['setup_local_tracking'])
  })

  it('keeps bulk import as an explicit advanced alternative', async () => {
    render(<App />)
    await screen.findByRole('button', { name: 'Start local tracking' })
    fireEvent.click(screen.getByText('Advanced credential import'))
    fireEvent.click(screen.getByRole('button', { name: 'Import all old credentials' }))
    await screen.findByText('Desktop')
    expect(preparations().map((call) => call.args.action)).toEqual(['migrate_vault'])
  })

  it('can explicitly import remaining credentials before any workspace workers mount', async () => {
    current = { ...encrypted, credentialSetupPending: true }
    render(<App />)
    fireEvent.click(await screen.findByRole('button', { name: 'Import remaining credentials' }))
    await screen.findByText('Desktop')
    expect(preparations().map((call) => call.args.action)).toEqual(['migrate_vault'])
  })

  it('locked encrypted storage never prompts automatically and authorizes only after explicit click', async () => {
    current = encrypted
    storageReady = false
    render(<App />)
    const button = await screen.findByRole('button', { name: 'Authorize local tracking storage' })
    expect(queryNames()).toEqual(['vault_status', 'vault_readiness'])
    expect(preparations()).toEqual([])
    storageReady = true
    fireEvent.click(button)
    await screen.findByText('Desktop')
    expect(preparations()).toEqual([{
      command: 'workspace_prepare', args: { action: 'authorize_tracking_storage', params: {} },
    }])
    expect(executions()).toHaveLength(1)
    expect(queryNames().slice(0, 4)).toEqual(['vault_status', 'vault_readiness', 'vault_status', 'vault_readiness'])
  })

  it('failed explicit authorization stays paused without automatic retries or reset', async () => {
    current = encrypted
    storageReady = false
    prepareError = 'Native authorization canceled'
    render(<App />)
    fireEvent.click(await screen.findByRole('button', { name: 'Authorize local tracking storage' }))
    await screen.findByRole('alert')
    expect(preparations()).toHaveLength(1)
    expect(executions()).toHaveLength(0)
    expect(queryNames()).toEqual(['vault_status', 'vault_readiness'])
    expect(screen.queryByText('Desktop')).toBeNull()
  })
})
