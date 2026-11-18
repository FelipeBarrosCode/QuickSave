import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { invoke, isTauri } from '@tauri-apps/api/core'
import { open, save } from '@tauri-apps/plugin-dialog'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import App from './App'
import { record, type AppTracking } from './api'
import { bytes } from './format'
import { activity, appTracking, batchPreview, batchStatus, bundle, dashboard, files, importDiscovery, paths, preview, provider, respond, restorePreview, software, type Call } from './test/fixtures'
import { createLocalInventoryFixture } from './test/localInventory'
import { catalogBackendFixture } from './test/backendFixtures'

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: vi.fn(() => true) }))
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: vi.fn() }))
let calls: Call[]
let nativeDashboard = structuredClone(dashboard)
let nativeTracking: AppTracking
let nativeDiscovery: unknown
let nativeRestorePreview: unknown
let nativeBatchPreview: unknown
let executeResult: unknown
let action: string
beforeEach(() => {
  calls = []
  action = ''
  nativeDashboard = structuredClone(dashboard)
  nativeTracking = structuredClone(appTracking)
  nativeDiscovery = structuredClone(importDiscovery)
  nativeRestorePreview = structuredClone(restorePreview)
  nativeBatchPreview = structuredClone(batchPreview)
  executeResult = undefined
  vi.mocked(isTauri).mockReturnValue(true)
  vi.mocked(open).mockReset()
  vi.mocked(save).mockReset()
  vi.mocked(invoke).mockImplementation(async (command, args) => {
    calls.push({ command, args: structuredClone(args ?? {}) as Record<string, unknown> })
    if (command === 'workspace_prepare') { action = String(record(args)?.action); return { ticketId: `ticket-${action}` } }
    if (command === 'workspace_execute') {
      if (action === 'preview_delete') return preview
      if (action === 'preview_restore') return nativeRestorePreview
      if (action === 'preview_upload_all') return nativeBatchPreview
      if (action === 'discover_noland_import') return nativeDiscovery
      return executeResult ?? nativeDashboard
    }
    if (record(args)?.query === 'dashboard') return nativeDashboard
    if (record(args)?.query === 'app_tracking') return nativeTracking
    return respond(command, args as Record<string, unknown>)
  })
})
afterEach(cleanup)
const preparations = () => calls.filter((call) => call.command === 'workspace_prepare')
function deferExecution() {
  let resolve!: (value: unknown) => void
  let reject!: (reason: Error) => void
  const original = vi.mocked(invoke).getMockImplementation()!
  vi.mocked(invoke).mockImplementation(async (command, args) => {
    if (command !== 'workspace_execute') return original(command, args)
    calls.push({ command, args: structuredClone(args ?? {}) as Record<string, unknown> })
    return new Promise((success, failure) => { resolve = success; reject = failure })
  })
  return { resolve: (value: unknown) => resolve(value), reject: (reason: Error) => reject(reason) }
}
async function ready() {
  render(<App />)
  await screen.findByText('Desktop')
}
async function backup() {
  await ready()
  fireEvent.click(screen.getByRole('button', { name: 'Backup' }))
}
async function restore() {
  await ready()
  fireEvent.click(screen.getByRole('button', { name: 'Restore' }))
  fireEvent.click(screen.getByRole('button', { name: /Test drive drive/ }))
  await screen.findByRole('button', { name: /Test backup/ })
  fireEvent.click(screen.getByRole('button', { name: /Test backup/ }))
}
async function providers() {
  await ready()
  const opener = screen.getByRole('button', { name: 'Connect providers' })
  opener.focus()
  fireEvent.click(opener)
  const dialog = screen.getByRole('dialog', { name: 'Connect providers' })
  await within(dialog).findByLabelText('Cloud provider')
  return dialog
}

describe('simple three-page workspace', () => {
  it('has exactly Overview, Backup and Restore navigation and no legacy forms or hero', async () => {
    await ready()
    const navigation = screen.getByRole('navigation', { name: 'Main navigation' })
    expect(within(navigation).getAllByRole('button').map((button) => button.textContent)).toEqual(['Overview', 'Backup', 'Restore'])
    expect(screen.queryByText('Capabilities')).toBeNull()
    expect(screen.queryByText(/recovery.key/i)).toBeNull()
    expect(screen.queryByText(/repository folder/i)).toBeNull()
    expect(screen.queryByText(/A safer place/i)).toBeNull()
    expect(screen.getAllByText('Needs backup')).toHaveLength(2)
    expect(screen.getByRole('heading', { name: 'Cloud providers' })).toBeTruthy()
    expect(calls.every((call) => call.command === 'workspace_query')).toBe(true)
  })
  it('disables native actions in browser preview without data or native calls', () => {
    vi.mocked(isTauri).mockReturnValue(false)
    render(<App />)
    expect(screen.getByText(/Browser preview only/)).toBeTruthy()
    expect((screen.getByRole('button', { name: 'Connect providers' }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: 'Backup' }))
    expect((screen.getByRole('button', { name: 'Enable app tracking' }) as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByRole('button', { name: 'Add files' }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.queryByText(software.name)).toBeNull()
    expect(invoke).not.toHaveBeenCalled()
    expect(open).not.toHaveBeenCalled()
  })
  it('renders long untrusted names as bounded text with no HTML interpretation', async () => {
    const long = `<img src=x onerror=bad()>${'long-software-name-'.repeat(100)}`
    nativeDashboard.software[0].name = long
    await backup()
    const title = screen.getByTitle(long)
    expect(title.className).toContain('truncate')
    expect(title.textContent).toBe(long)
    expect(title.querySelector('img')).toBeNull()
  })
  it('bounds discovered software DOM and provides explicit pagination', async () => {
    nativeDashboard.software = Array.from({ length: 1000 }, (_, index) => ({
      ...software, id: `software-${index}`, name: `Test software ${index}`,
    }))
    await backup()
    expect(screen.getAllByRole('button', { name: /^Browse files for/ })).toHaveLength(20)
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    expect(screen.getByTitle('Test software 20')).toBeTruthy()
    expect(screen.queryByTitle('Test software 0')).toBeNull()
  })
})

describe('provider sheet and native privacy', () => {
  it('loads provider schemas only on demand and uses native OAuth without token inputs', async () => {
    await ready()
    expect(calls.some((call) => call.args.query === 'provider_types')).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Connect providers' }))
    const dialog = screen.getByRole('dialog', { name: 'Connect providers' })
    await within(dialog).findByLabelText('Cloud provider')
    fireEvent.change(within(dialog).getByLabelText('Client secret (optional)'), { target: { value: 'test-private-secret' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Continue with native OAuth' }))
    await waitFor(() => expect(preparations()).toHaveLength(1))
    expect(preparations()[0].args).toEqual({ action: 'connect_oauth', params: {
      kind: 'drive', name: 'Google Drive', clientSecret: 'test-private-secret', fields: {},
    } })
    expect((within(dialog).getByLabelText('Client secret (optional)') as HTMLInputElement).value).toBe('')
    expect(screen.queryByText('test-private-secret')).toBeNull()
    expect(within(dialog).queryByLabelText(/token/i)).toBeNull()
  })
  it('renders required private provider fields dynamically and clears them after a failed call', async () => {
    const dialog = await providers()
    fireEvent.change(within(dialog).getByLabelText('Cloud provider'), { target: { value: 's3' } })
    for (const [label, value] of [['Bucket', 'test-bucket'], ['Access key', 'test-access'], ['Secret key', 'test-secret'], ['Region', 'isolated-test']]) {
      fireEvent.change(within(dialog).getByLabelText(label), { target: { value } })
    }
    expect((within(dialog).getByLabelText('Secret key') as HTMLInputElement).type).toBe('password')
    expect((within(dialog).getByLabelText('Access key') as HTMLInputElement).required).toBe(true)
    vi.mocked(invoke).mockRejectedValueOnce(new Error('backend echoed test-secret'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Connect provider' }))
    await within(dialog).findByRole('alert')
    expect((within(dialog).getByLabelText('Secret key') as HTMLInputElement).value).toBe('')
    expect(dialog.textContent).not.toContain('test-secret')
    expect(calls.some((call) => call.command === 'workspace_execute')).toBe(false)
  })
  it('sends No Land credential type/value and separate bucket/prefix fields without leaking secrets', async () => {
    const dialog = await providers()
    fireEvent.change(within(dialog).getByLabelText('Cloud provider'), { target: { value: 's3' } })
    for (const [label, value] of [
      ['Bucket', 'test-bucket'], ['Access key', 'test-access'], ['Secret key', 'test-secret'],
      ['Region', 'isolated-test'], ['Folder / prefix (optional)', 'test-prefix'],
    ]) fireEvent.change(within(dialog).getByLabelText(label), { target: { value } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Connect provider' }))
    await waitFor(() => expect(preparations()).toHaveLength(1))
    expect(preparations()[0].args).toEqual({ action: 'connect_provider', params: {
      kind: 's3', name: 'S3', bucket: 'test-bucket', prefix: 'test-prefix', fields: { region: 'isolated-test' },
      credentials: { type: 's3', value: { access_key_id: 'test-access', secret_access_key: 'test-secret' } },
    } })
    expect(dialog.textContent).not.toContain('test-secret')
    expect((within(dialog).getByLabelText('Secret key') as HTMLInputElement).value).toBe('')
  })
  it('automatically discovers and imports one native No Land source without asking for a file path', async () => {
    const dialog = await providers()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Import No Land' }))
    await waitFor(() => expect(preparations()).toHaveLength(2))
    expect(preparations().map((call) => call.args)).toEqual([
      { action: 'discover_noland_import', params: {} },
      { action: 'import_noland', params: { sourceId: 'noland-source-test' } },
    ])
    expect(calls[ calls.findIndex((call) => call.command === 'workspace_prepare') + 1 ]).toEqual({
      command: 'workspace_execute', args: { ticketId: 'ticket-discover_noland_import' },
    })
    expect(open).not.toHaveBeenCalled()
    expect(within(dialog).queryByLabelText('No Land source')).toBeNull()
    expect(calls.some((call) => call.args.query === 'noland_import_preview')).toBe(false)
    expect(calls.every((call) => !/state|keychain|vault/.test(call.command))).toBe(true)
  })
  it('does not execute discovery or import when native discovery consent is cancelled', async () => {
    const dialog = await providers()
    vi.mocked(invoke).mockRejectedValueOnce(new Error('Native discovery cancelled'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Import No Land' }))
    await within(dialog).findByText('Native discovery cancelled')
    expect(preparations()).toHaveLength(0)
    expect(calls.some((call) => call.command === 'workspace_execute')).toBe(false)
    expect(open).not.toHaveBeenCalled()
  })
  it('asks for a source only when native discovery returns several unresolved candidates', async () => {
    nativeDiscovery = { candidates: [
      importDiscovery.candidates[0],
      { id: 'noland-source-other', label: 'Other isolated No Land source', path: '/isolated-test/other/state.json', profileCount: 2 },
    ] }
    const dialog = await providers()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Import No Land' }))
    const chooser = await within(dialog).findByLabelText('No Land source')
    expect(preparations().map((call) => call.args.action)).toEqual(['discover_noland_import'])
    expect(open).not.toHaveBeenCalled()
    fireEvent.change(chooser, { target: { value: 'noland-source-other' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Import selected No Land source' }))
    await waitFor(() => expect(preparations()).toHaveLength(2))
    expect(preparations()[1].args).toEqual({ action: 'import_noland', params: { sourceId: 'noland-source-other' } })
    expect(open).not.toHaveBeenCalled()
  })
  it('cancels multiple-source selection without importing or opening a file picker', async () => {
    nativeDiscovery = { candidates: [
      importDiscovery.candidates[0],
      { id: 'noland-source-other', label: 'Other isolated source', path: '/isolated-test/other/state.json' },
    ] }
    const dialog = await providers()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Import No Land' }))
    await within(dialog).findByLabelText('No Land source')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel source selection' }))
    expect(within(dialog).queryByLabelText('No Land source')).toBeNull()
    expect(preparations().map((call) => call.args.action)).toEqual(['discover_noland_import'])
    expect(open).not.toHaveBeenCalled()
  })
  it('uses a native-selected source without a redundant chooser or a JS path search', async () => {
    nativeDiscovery = { candidates: [
      importDiscovery.candidates[0],
      { id: 'noland-selected', label: 'Native selected source', path: '/isolated-test/native-selected/state.json' },
    ], selectedId: 'noland-selected' }
    const dialog = await providers()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Import No Land' }))
    await waitFor(() => expect(preparations()).toHaveLength(2))
    expect(preparations()[1].args).toEqual({ action: 'import_noland', params: { sourceId: 'noland-selected' } })
    expect(within(dialog).queryByLabelText('No Land source')).toBeNull()
    expect(open).not.toHaveBeenCalled()
  })
  it('reports no discovered source without creating a candidate or asking for a state-file path', async () => {
    nativeDiscovery = { candidates: [] }
    const dialog = await providers()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Import No Land' }))
    await within(dialog).findByText('No No Land state.json was found in the approved locations.')
    expect(within(dialog).queryByLabelText('No Land source')).toBeNull()
    expect(preparations().map((call) => call.args.action)).toEqual(['discover_noland_import'])
    expect(open).not.toHaveBeenCalled()
    expect(within(dialog).getByText('Advanced import').closest('details')?.open).toBe(false)
  })
  it('retains an explicitly advanced manual JSON picker and does nothing when it is cancelled', async () => {
    const dialog = await providers()
    fireEvent.click(within(dialog).getByText('Advanced import'))
    vi.mocked(open).mockResolvedValueOnce(null).mockResolvedValueOnce(paths.stateFile)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Choose state.json manually' }))
    await waitFor(() => expect(open).toHaveBeenCalledTimes(1))
    await waitFor(() => expect((within(dialog).getByRole('button', { name: 'Choose state.json manually' }) as HTMLButtonElement).disabled).toBe(false))
    expect(preparations()).toHaveLength(0)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Choose state.json manually' }))
    await waitFor(() => expect(preparations()).toHaveLength(1))
    expect(preparations()[0].args).toEqual({ action: 'import_noland', params: { stateFile: paths.stateFile } })
  })
  it('rejects an invalid native selected source instead of deriving one from its path', async () => {
    nativeDiscovery = { ...importDiscovery, selectedId: 'not-discovered' }
    const dialog = await providers()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Import No Land' }))
    await within(dialog).findByText('The selected No Land source is not in the native discovery result.')
    expect(preparations().map((call) => call.args.action)).toEqual(['discover_noland_import'])
    expect(open).not.toHaveBeenCalled()
  })
  it('offers a separate native write grant for read-only imports and does not claim it early', async () => {
    nativeDashboard.providers[0].readOnly = true
    nativeDashboard.providers[0].origin = 'noland'
    const dialog = await providers()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Enable uploads' }))
    await waitFor(() => expect(preparations()).toHaveLength(1))
    expect(preparations()[0].args).toEqual({ action: 'authorize_provider_writes', params: { providerId: provider.id } })
    expect(within(dialog).getByText(/Read-only/)).toBeTruthy()
  })
  it('keeps unverified provider status explicit and excludes it from restore connections', async () => {
    nativeDashboard.providers[0].status = 'error'
    nativeDashboard.providers[0].error = 'Test health verification unavailable'
    nativeDashboard.summary.connectedProviders = 0
    const dialog = await providers()
    expect(within(dialog).getByText('error')).toBeTruthy()
    expect(within(dialog).getByText('Test health verification unavailable')).toBeTruthy()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close connect providers' }))
    fireEvent.click(screen.getByRole('button', { name: 'Restore' }))
    expect(screen.queryByRole('button', { name: /Test drive drive/ })).toBeNull()
  })
  it('refreshes a newly configured profile after failed health verification without calling it connected', async () => {
    nativeDashboard.providers = []
    nativeDashboard.summary.connectedProviders = 0
    const dialog = await providers()
    nativeDashboard.providers = [{ ...provider, status: 'error', error: 'Provider access has not been verified.' }]
    vi.mocked(invoke).mockRejectedValueOnce(new Error('test health failure'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Continue with native OAuth' }))
    await within(dialog).findByText('Provider access has not been verified.')
    expect(within(dialog).getByText('error')).toBeTruthy()
    expect(within(dialog).queryByText('connected')).toBeNull()
  })
  it.each(['error', 'connecting'] as const)('rechecks a %s profile with exact native consent and never claims success after failure', async (status) => {
    nativeDashboard.providers[0] = { ...provider, status, readOnly: true, origin: 'noland' }
    nativeDashboard.summary.connectedProviders = 0
    const dialog = await providers()
    const pending = deferExecution()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Check connection' }))
    const checking = await within(dialog).findByRole('button', { name: 'Checking connection…' }) as HTMLButtonElement
    await waitFor(() => expect(calls.some((call) => call.command === 'workspace_execute')).toBe(true))
    expect(checking.disabled).toBe(true)
    expect(checking.getAttribute('aria-busy')).toBe('true')
    expect(within(dialog).getByText(`${status} · Read-only`)).toBeTruthy()
    expect(within(dialog).queryByText('connected · Read-only')).toBeNull()
    fireEvent.click(checking)
    const prepareIndex = calls.findIndex((call) => call.command === 'workspace_prepare')
    expect(calls.slice(prepareIndex, prepareIndex + 2)).toEqual([
      { command: 'workspace_prepare', args: { action: 'verify_provider', params: { providerId: provider.id } } },
      { command: 'workspace_execute', args: { ticketId: 'ticket-verify_provider' } },
    ])
    await act(async () => { pending.reject(new Error('Read-only health check is still offline')) })
    await within(dialog).findByText('Read-only health check is still offline')
    const retry = within(dialog).getByRole('button', { name: 'Check connection' }) as HTMLButtonElement
    await waitFor(() => expect(retry.disabled).toBe(false))
    expect(within(dialog).getByText(`${status} · Read-only`)).toBeTruthy()
    expect(within(dialog).queryByText('connected · Read-only')).toBeNull()
    expect((within(dialog).getByRole('button', { name: 'Enable uploads' }) as HTMLButtonElement).disabled).toBe(true)
    expect(preparations()).toHaveLength(1)
    expect(calls.filter((call) => call.command === 'workspace_execute')).toHaveLength(1)
  })
  it('updates only the selected profile after a native-confirmed health check and keeps read-only policy', async () => {
    nativeDashboard.providers = [
      { ...provider, status: 'error', readOnly: true, origin: 'noland' },
      { ...provider, id: 'provider-other', name: 'Other test provider', status: 'connecting' },
    ]
    nativeDashboard.summary.connectedProviders = 0
    const dialog = await providers()
    const row = within(dialog).getByTitle(provider.name).closest('li')!
    const otherRow = within(dialog).getByTitle('Other test provider').closest('li')!
    const pending = deferExecution()
    fireEvent.click(within(row).getByRole('button', { name: 'Check connection' }))
    await within(row).findByRole('button', { name: 'Checking connection…' })
    await waitFor(() => expect(calls.some((call) => call.command === 'workspace_execute')).toBe(true))
    expect((within(otherRow).getByRole('button', { name: 'Check connection' }) as HTMLButtonElement).disabled).toBe(true)
    expect(within(row).getByText('error · Read-only')).toBeTruthy()
    const confirmed = structuredClone(nativeDashboard)
    confirmed.providers[0].status = 'connected'
    confirmed.providers[0].error = null
    confirmed.summary.connectedProviders = 1
    await act(async () => { pending.resolve(confirmed) })
    await within(row).findByText('connected · Read-only')
    expect(within(row).queryByRole('button', { name: 'Check connection' })).toBeNull()
    expect(within(otherRow).getByText('connecting')).toBeTruthy()
    expect(preparations()[0].args).toEqual({ action: 'verify_provider', params: { providerId: provider.id } })
    expect(preparations().some((call) => call.args.action === 'authorize_provider_writes')).toBe(false)
  })
  it.each(['connected', 'disconnected'] as const)('does not offer a check for a %s profile', async (status) => {
    nativeDashboard.providers[0].status = status
    const dialog = await providers()
    expect(within(dialog).queryByRole('button', { name: 'Check connection' })).toBeNull()
    expect(preparations()).toHaveLength(0)
  })
  it('traps keyboard focus, restores it on close, and preserves main scroll position', async () => {
    const dialog = await providers()
    const scroll = document.querySelector('.main-scroll')!
    scroll.scrollTop = 230
    const last = within(dialog).getByRole('button', { name: 'Disconnect' })
    last.focus()
    fireEvent.keyDown(dialog, { key: 'Tab' })
    expect(document.activeElement).toBe(within(dialog).getByRole('button', { name: 'Close connect providers' }))
    fireEvent.keyDown(dialog, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Connect providers' }))
    expect(scroll.scrollTop).toBe(230)
  })
})

describe('provider reauthorization and private recovery-key export', () => {
  it('reauthorizes an existing OAuth provider through native approval only, keeping imported read-only status', async () => {
    nativeDashboard.providers[0] = { ...provider, readOnly: true, origin: 'noland', status: 'error' }
    const dialog = await providers()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Reauthorize' }))
    await waitFor(() => expect(preparations()).toHaveLength(1))
    expect(preparations()[0].args).toEqual({ action: 'reauthorize_provider', params: { providerId: provider.id } })
    expect(within(dialog).getByText('error · Read-only')).toBeTruthy()
    expect(preparations().some((call) => call.args.action === 'authorize_provider_writes')).toBe(false)
  })
  it('allows only credential fields for static reauthorization and clears them on a failed native request', async () => {
    nativeDashboard.providers[0].kind = 's3'
    const sheet = await providers()
    fireEvent.click(within(sheet).getByRole('button', { name: 'Reauthorize' }))
    const dialog = screen.getByRole('dialog', { name: 'Reauthorize provider' })
    expect(within(dialog).queryByLabelText('Bucket')).toBeNull()
    expect(within(dialog).queryByLabelText('Region')).toBeNull()
    expect(within(dialog).queryByLabelText('Connection name')).toBeNull()
    fireEvent.change(within(dialog).getByLabelText('Access key'), { target: { value: 'synthetic-new-access' } })
    fireEvent.change(within(dialog).getByLabelText('Secret key'), { target: { value: 'synthetic-new-secret' } })
    vi.mocked(invoke).mockRejectedValueOnce(new Error('native echoed synthetic-new-secret'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Reauthorize with native confirmation' }))
    await within(dialog).findByRole('alert')
    expect((within(dialog).getByLabelText('Secret key') as HTMLInputElement).value).toBe('')
    expect(dialog.textContent).not.toContain('synthetic-new-secret')
    expect(calls.some((call) => call.command === 'workspace_execute')).toBe(false)
  })
  it('sends the existing native credential type but no bucket, root, prefix or client edits', async () => {
    nativeDashboard.providers[0].kind = 's3'
    const sheet = await providers()
    fireEvent.click(within(sheet).getByRole('button', { name: 'Reauthorize' }))
    const dialog = screen.getByRole('dialog', { name: 'Reauthorize provider' })
    fireEvent.change(within(dialog).getByLabelText('Access key'), { target: { value: 'synthetic-access' } })
    fireEvent.change(within(dialog).getByLabelText('Secret key'), { target: { value: 'synthetic-secret' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Reauthorize with native confirmation' }))
    await waitFor(() => expect(preparations()).toHaveLength(1))
    expect(preparations()[0].args).toEqual({ action: 'reauthorize_provider', params: {
      providerId: provider.id, credentials: { type: 's3', value: {
        access_key_id: 'synthetic-access', secret_access_key: 'synthetic-secret',
      } },
    } })
    await screen.findByRole('dialog', { name: 'Connect providers' })
  })
  it('allows a disconnected provider recovery export but offers no reauthorization or reconnection shortcut', async () => {
    nativeDashboard.providers[0].status = 'disconnected'
    const dialog = await providers()
    expect(within(dialog).queryByRole('button', { name: 'Reauthorize' })).toBeNull()
    expect((within(dialog).getByRole('button', { name: 'Export recovery key' }) as HTMLButtonElement).disabled).toBe(false)
    vi.mocked(save).mockResolvedValueOnce(null)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Export recovery key' }))
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1))
    expect(preparations()).toHaveLength(0)
    expect(open).not.toHaveBeenCalled()
  })
  it('exports through a separate exact-destination ticket and renders only a non-secret native receipt', async () => {
    executeResult = { written: true, keyMaterialReturned: false, format: 'external_32_byte_repository_key' }
    vi.mocked(save).mockResolvedValueOnce('/isolated-test/external/fixture-recovery.key')
    const dialog = await providers()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Export recovery key' }))
    await within(dialog).findByText(/Recovery-key file exported with native protection/)
    expect(preparations()[0].args).toEqual({ action: 'export_recovery_key', params: {
      providerId: provider.id, destination: '/isolated-test/external/fixture-recovery.key',
    } })
    expect(calls.find((call) => call.command === 'workspace_execute')?.args).toEqual({ ticketId: 'ticket-export_recovery_key' })
    expect(dialog.textContent).not.toContain('external_32_byte_repository_key')
    expect(open).not.toHaveBeenCalled()
  })
  it('does not retry, overwrite or claim an export after the native new-file publication is denied', async () => {
    vi.mocked(save).mockResolvedValueOnce('/isolated-test/external/existing.key')
    const dialog = await providers()
    vi.mocked(invoke).mockRejectedValueOnce(new Error('Destination already exists; no recovery key was overwritten'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Export recovery key' }))
    await within(dialog).findByText('Destination already exists; no recovery key was overwritten')
    expect(within(dialog).queryByText(/Recovery-key file exported/)).toBeNull()
    expect(calls.some((call) => call.command === 'workspace_execute')).toBe(false)
    expect(save).toHaveBeenCalledTimes(1)
  })
})

describe('software backup and exact file subsets', () => {
  it('enables automatic app tracking for exact native roles without a per-app folder picker', async () => {
    nativeTracking.enabled = false
    await backup()
    fireEvent.click(screen.getByRole('button', { name: 'Enable app tracking' }))
    await waitFor(() => expect(preparations()).toHaveLength(1))
    expect(preparations()[0].args).toEqual({ action: 'enable_app_tracking', params: {
      enabled: true, defaultProviderId: provider.id, roles: ['installation', 'save', 'config', 'runtime'],
    } })
    expect(calls.find((call) => call.command === 'workspace_execute')?.args).toEqual({ ticketId: 'ticket-enable_app_tracking' })
    expect(open).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Enable app tracking' })).toBeTruthy()
  })
  it('never renders metadata-only discovery as a bundle or offers a per-app Track button', async () => {
    nativeDashboard.software[0].tracked = false
    nativeDashboard.software[0].status = 'not_tracked'
    nativeTracking.diagnostics = [{ appId: software.appId, name: software.name, code: 'missing_permission', message: 'Native permission is missing for this actual source.' }]
    await backup()
    const list = screen.getByRole('region', { name: 'Software' })
    expect(within(list).queryByTitle(software.name)).toBeNull()
    expect(screen.queryByRole('button', { name: 'Track' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Add software' })).toBeNull()
    const diagnostic = screen.getByText('Native permission is missing for this actual source.')
    expect(diagnostic.closest('details')?.open).toBe(false)
    expect(open).not.toHaveBeenCalled()
    expect(preparations()).toHaveLength(0)
  })
  it('completes one enable-all flow with inventory indexed from isolated real fixture roots', async () => {
    const fixture = createLocalInventoryFixture()
    try {
      nativeDashboard.software = []
      nativeTracking = { enabled: false, scanning: false, completedApps: 0, totalApps: 0, diagnostics: [] }
      await backup()
      expect(screen.queryByRole('button', { name: /^Browse files for/ })).toBeNull()
      const original = vi.mocked(invoke).getMockImplementation()!
      vi.mocked(invoke).mockImplementation(async (command, args) => {
        if (command === 'workspace_execute' && action === 'enable_app_tracking') {
          nativeDashboard.software = [{ ...fixture.software, providerId: provider.id }]
          nativeTracking = { enabled: true, scanning: false, completedApps: 1, totalApps: 1, diagnostics: [] }
        }
        if (record(args)?.query === 'software_files') return { files: fixture.files }
        return original(command, args)
      })
      fireEvent.click(screen.getByRole('button', { name: 'Enable app tracking' }))
      const browse = await screen.findByRole('button', { name: `Browse files for ${fixture.software.name}` })
      fireEvent.click(browse)
      await screen.findByRole('checkbox', { name: 'Select slot.sav' })
      const inventory = screen.getByRole('region', { name: `Local inventory for ${fixture.software.name}` })
      expect(within(inventory).getByText(`${fixture.files.length} files · ${bytes(fixture.software.logicalBytes ?? null)}`)).toBeTruthy()
      for (const root of fixture.software.roots!) {
        expect(within(inventory).getByTitle(root.path)).toBeTruthy()
        expect(within(inventory).getByText(root.role!)).toBeTruthy()
      }
      expect(screen.getAllByRole('button', { name: /^Hide files for/ })).toHaveLength(1)
      expect(screen.getAllByRole('checkbox', { name: /^Select / })).toHaveLength(fixture.files.length)
      expect(preparations().map((call) => call.args.action)).toEqual(['enable_app_tracking'])
      expect(calls.filter((call) => call.args.query === 'app_tracking')).toHaveLength(2)
      expect(open).not.toHaveBeenCalled()
    } finally { fixture.dispose() }
  })
  it('reconciles new apps and gaps only through a fresh native exact-scope refresh', async () => {
    await backup()
    fireEvent.click(screen.getByRole('button', { name: 'Refresh app tracking' }))
    await waitFor(() => expect(preparations()).toHaveLength(1))
    expect(preparations()[0].args).toEqual({ action: 'refresh_app_tracking', params: {} })
    expect(open).not.toHaveBeenCalled()
  })
  it('shows only native scan counts and keeps diagnostics separate from local bundle rows', async () => {
    nativeTracking = {
      enabled: true, scanning: true, completedApps: 2, totalApps: 7,
      diagnostics: [{ name: 'Diagnostic-only app', code: 'missing_permission', message: 'Actual root permission was denied.' }],
    }
    await backup()
    const tracking = screen.getByRole('region', { name: 'App tracking' })
    expect(within(tracking).getByText('Checking apps: 2 / 7')).toBeTruthy()
    const progress = within(tracking).getByRole('progressbar', { name: 'Apps checked' }) as HTMLProgressElement
    expect(progress.value).toBe(2)
    expect(progress.max).toBe(7)
    expect(screen.getAllByRole('button', { name: /^Browse files for/ })).toHaveLength(1)
    expect(within(screen.getByRole('region', { name: 'Software' })).queryByText('Diagnostic-only app')).toBeNull()
  })
  it('keeps app-tracking permission off when native consent is rejected', async () => {
    nativeTracking.enabled = false
    await backup()
    vi.mocked(invoke).mockRejectedValueOnce(new Error('Native app-tracking approval cancelled'))
    fireEvent.click(screen.getByRole('button', { name: 'Enable app tracking' }))
    await screen.findByText('Native app-tracking approval cancelled')
    expect(screen.getByRole('button', { name: 'Enable app tracking' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Refresh app tracking' })).toBeNull()
    expect(open).not.toHaveBeenCalled()
  })
  it('adds individual native-picked files and does nothing after cancellation', async () => {
    await backup()
    vi.mocked(open).mockResolvedValueOnce(null).mockResolvedValueOnce([paths.file])
    fireEvent.click(screen.getByRole('button', { name: 'Add files' }))
    await waitFor(() => expect((screen.getByRole('button', { name: 'Add files' }) as HTMLButtonElement).disabled).toBe(false))
    expect(preparations()).toHaveLength(0)
    fireEvent.click(screen.getByRole('button', { name: 'Add files' }))
    await waitFor(() => expect(preparations()).toHaveLength(1))
    expect(preparations()[0].args).toEqual({ action: 'add_files', params: { paths: [paths.file], providerId: provider.id } })
  })
  it('keeps autosave off after native rejection or network failure', async () => {
    await backup()
    const toggle = screen.getByRole('switch', { name: `Autosave for ${software.name}` }) as HTMLInputElement
    vi.mocked(invoke).mockRejectedValueOnce('network offline')
    fireEvent.click(toggle)
    await screen.findByRole('alert')
    expect(toggle.checked).toBe(false)
    expect(screen.getByText('Keep local files; upload changes in background.')).toBeTruthy()
    expect(calls.some((call) => call.command === 'workspace_execute')).toBe(false)
  })
  it('does not enable autosave until updated native workspace state says so', async () => {
    await backup()
    const toggle = screen.getByRole('switch', { name: `Autosave for ${software.name}` }) as HTMLInputElement
    fireEvent.click(toggle)
    await waitFor(() => expect(preparations()).toHaveLength(1))
    expect(preparations()[0].args).toEqual({ action: 'set_autosave', params: {
      softwareId: software.id, providerId: provider.id, enabled: true,
    } })
    expect(toggle.checked).toBe(false)
  })
  it('loads files lazily and sends only checked fileIds for an individual upload', async () => {
    await backup()
    expect(calls.some((call) => call.args.query === 'software_files')).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: `Browse files for ${software.name}` }))
    fireEvent.click(await screen.findByRole('checkbox', { name: `Select ${files[1].path}` }))
    fireEvent.click(screen.getByRole('button', { name: 'Upload selected (1)' }))
    await waitFor(() => expect(preparations()).toHaveLength(1))
    expect(preparations()[0].args).toEqual({ action: 'upload', params: {
      softwareId: software.id, providerId: provider.id, fileIds: [files[1].id],
    } })
  })
  it('replaces file pages rather than appending an unbounded DOM', async () => {
    await backup()
    const original = vi.mocked(invoke).getMockImplementation()!
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (record(args)?.query === 'software_files') return record(record(args)?.params)?.cursor
        ? { files: [{ ...files[0], id: 'next-file', path: 'next-file.json' }] }
        : { files, nextCursor: 'next-test-cursor' }
      return original(command, args)
    })
    fireEvent.click(screen.getByRole('button', { name: `Browse files for ${software.name}` }))
    await screen.findByRole('checkbox', { name: `Select ${files[0].path}` })
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await screen.findByRole('checkbox', { name: 'Select next-file.json' })
    expect(screen.queryByRole('checkbox', { name: `Select ${files[0].path}` })).toBeNull()
  })
  it('leaves fileIds absent only for the explicit whole-software upload button', async () => {
    await backup()
    fireEvent.click(screen.getByRole('button', { name: 'Upload' }))
    await waitFor(() => expect(preparations()).toHaveLength(1))
    expect(preparations()[0].args.params).toEqual({ softwareId: software.id, providerId: provider.id })
  })
})

describe('provider-based restore and frozen deletion', () => {
  it('opens connected provider cards before bundles, never an arbitrary source path', async () => {
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Restore' }))
    expect(calls.some((call) => call.args.query === 'bundles')).toBe(false)
    expect(screen.getByRole('button', { name: /Test drive drive/ })).toBeTruthy()
    expect(screen.queryByRole('textbox')).toBeNull()
    expect(screen.getByRole('button', { name: 'Connect providers' })).toBeTruthy()
  })
  it('freezes checked file IDs and a native-picked destination before a separately confirmed download', async () => {
    await restore()
    fireEvent.click(screen.getByRole('button', { name: 'Browse individual files' }))
    fireEvent.click(await screen.findByRole('checkbox', { name: `Select ${files[0].path}` }))
    vi.mocked(open).mockResolvedValueOnce(paths.destination)
    fireEvent.click(screen.getByRole('button', { name: 'Download selected (1)' }))
    await waitFor(() => expect(preparations()).toHaveLength(1))
    expect(preparations()[0].args).toEqual({ action: 'preview_restore', params: {
      providerId: provider.id, bundleId: bundle.id, appId: bundle.appId,
      destination: paths.destination, fileIds: [files[0].id], mode: 'create_new',
    } })
    const dialog = await screen.findByRole('dialog', { name: 'Review restore' })
    expect(preparations().some((call) => call.args.action === 'download')).toBe(false)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore with native confirmation' }))
    await waitFor(() => expect(preparations()).toHaveLength(2))
    expect(preparations()[1].args).toEqual({ action: 'download', params: {
      restorePreviewId: restorePreview.previewId, overwriteAcknowledgement: false,
    } })
    expect(calls.filter((call) => call.command === 'workspace_execute').map((call) => call.args))
      .toEqual([{ ticketId: 'ticket-preview_restore' }, { ticketId: 'ticket-download' }])
  })
  it('does not prepare a download if the destination picker is cancelled', async () => {
    await restore()
    vi.mocked(open).mockResolvedValueOnce(null)
    fireEvent.click(screen.getByRole('button', { name: 'Download backup' }))
    await waitFor(() => expect(open).toHaveBeenCalled())
    expect(preparations()).toHaveLength(0)
  })
  it('requires the real frozen overwrite acknowledgement for replace mode and sends no replacement paths', async () => {
    nativeRestorePreview = {
      ...restorePreview, requiresOverwriteAcknowledgement: true,
      conflicts: [{ path: 'settings.json', reason: 'Existing destination file' }],
    }
    await restore()
    fireEvent.click(screen.getByText('Restore options and backup details'))
    fireEvent.change(screen.getByLabelText('Restore mode'), { target: { value: 'replace' } })
    vi.mocked(open).mockResolvedValueOnce(paths.destination)
    fireEvent.click(screen.getByRole('button', { name: 'Download backup' }))
    const dialog = await screen.findByRole('dialog', { name: 'Review restore' })
    const confirm = within(dialog).getByRole('button', { name: 'Restore with native confirmation' }) as HTMLButtonElement
    expect(confirm.disabled).toBe(true)
    expect(preparations()[0].args).toEqual({ action: 'preview_restore', params: {
      providerId: provider.id, bundleId: bundle.id, appId: bundle.appId, destination: paths.destination, mode: 'replace',
    } })
    expect(within(dialog).getByText('Conflicts (1)').closest('details')?.open).toBe(false)
    expect(within(dialog).getByTitle(paths.destination)).toBeTruthy()
    fireEvent.click(confirm)
    expect(preparations()).toHaveLength(1)
    fireEvent.click(within(dialog).getByRole('checkbox', { name: /I acknowledge overwriting/ }))
    fireEvent.click(confirm)
    await waitFor(() => expect(preparations()).toHaveLength(2))
    expect(preparations()[1].args).toEqual({ action: 'download', params: {
      restorePreviewId: restorePreview.previewId, overwriteAcknowledgement: true,
    } })
    expect(open).toHaveBeenCalledTimes(1)
  })
  it('passes an explicit merge plan and allows cancelling its frozen preview without downloading', async () => {
    await restore()
    fireEvent.click(screen.getByText('Restore options and backup details'))
    fireEvent.change(screen.getByLabelText('Restore mode'), { target: { value: 'merge' } })
    vi.mocked(open).mockResolvedValueOnce(paths.destination)
    fireEvent.click(screen.getByRole('button', { name: 'Download backup' }))
    const dialog = await screen.findByRole('dialog', { name: 'Review restore' })
    expect(preparations()[0].args.params).toEqual({
      providerId: provider.id, bundleId: bundle.id, appId: bundle.appId, destination: paths.destination, mode: 'merge',
    })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(preparations().map((call) => call.args.action)).toEqual(['preview_restore'])
    expect(screen.queryByRole('dialog')).toBeNull()
  })
  it('never bypasses an unsupported native restore-preview API with a legacy direct download', async () => {
    await restore()
    const original = vi.mocked(invoke).getMockImplementation()!
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (command === 'workspace_prepare' && record(args)?.action === 'preview_restore') {
        calls.push({ command, args: structuredClone(args ?? {}) as Record<string, unknown> })
        throw new Error('Native restore preview is not available')
      }
      return original(command, args)
    })
    vi.mocked(open).mockResolvedValueOnce(paths.destination)
    fireEvent.click(screen.getByRole('button', { name: 'Download backup' }))
    await screen.findByText('Native restore preview is not available')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(preparations().map((call) => call.args.action)).toEqual(['preview_restore'])
    expect(calls.some((call) => call.command === 'workspace_execute')).toBe(false)
  })
  it('rejects a restore preview that echoes a different destination or malformed acknowledgement', async () => {
    nativeRestorePreview = { ...restorePreview, destination: '/isolated-test/other-destination' }
    await restore()
    vi.mocked(open).mockResolvedValueOnce(paths.destination)
    fireEvent.click(screen.getByRole('button', { name: 'Download backup' }))
    await screen.findByText('The restore preview belongs to a different restore plan.')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(preparations().map((call) => call.args.action)).toEqual(['preview_restore'])
  })
  it('does not reuse a frozen restore preview after the final native action is denied', async () => {
    await restore()
    vi.mocked(open).mockResolvedValueOnce(paths.destination)
    fireEvent.click(screen.getByRole('button', { name: 'Download backup' }))
    const dialog = await screen.findByRole('dialog', { name: 'Review restore' })
    vi.mocked(invoke).mockRejectedValueOnce(new Error('Native restore confirmation cancelled'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore with native confirmation' }))
    await screen.findByText('This restore preview has been submitted. Close and request a fresh preview before trying again.')
    const confirm = within(dialog).getByRole('button', { name: 'Restore with native confirmation' }) as HTMLButtonElement
    expect(confirm.disabled).toBe(true)
    fireEvent.click(confirm)
    expect(calls.filter((call) => call.command === 'workspace_execute')).toHaveLength(1)
  })
  it('keeps older native generations visible and uses their shared source IDs without latest-only placeholders', async () => {
    const older = {
      ...bundle, id: 'older-backup', name: 'Older backup', createdAt: '2026-11-16T10:00:00Z',
      sourceBundleId: 'shared-source-older-bundle', sourceAppId: 'shared-source-app',
    }
    const original = vi.mocked(invoke).getMockImplementation()!
    vi.mocked(invoke).mockImplementation(async (command, args) =>
      record(args)?.query === 'bundles' ? { bundles: [bundle, older] } : original(command, args))
    await restore()
    fireEvent.click(screen.getByRole('button', { name: /Older backup/ }))
    expect(screen.getByRole('button', { name: /Test backup/ })).toBeTruthy()
    fireEvent.click(screen.getByText('Restore options and backup details'))
    expect(screen.getByTitle(older.id)).toBeTruthy()
    expect(screen.getByTitle(older.sourceBundleId)).toBeTruthy()
    expect(screen.getByTitle(older.sourceAppId)).toBeTruthy()
    vi.mocked(open).mockResolvedValueOnce(paths.destination)
    fireEvent.click(screen.getByRole('button', { name: 'Download backup' }))
    await screen.findByRole('dialog', { name: 'Review restore' })
    expect(preparations()[0].args.params).toEqual({
      providerId: provider.id, bundleId: older.id, appId: older.appId, destination: paths.destination, mode: 'create_new',
    })
  })
  it('requires frozen preview, separate dependency checkbox, and final native preparation', async () => {
    await restore()
    fireEvent.click(screen.getByRole('button', { name: 'Delete cloud backup' }))
    const dialog = await screen.findByRole('dialog', { name: 'Delete cloud backup' })
    expect(preparations().map((call) => call.args.action)).toEqual(['preview_delete'])
    const confirm = within(dialog).getByRole('button', { name: 'Delete with native confirmation' }) as HTMLButtonElement
    expect(confirm.disabled).toBe(true)
    expect(within(dialog).getByText('Dependent test backup')).toBeTruthy()
    fireEvent.click(within(dialog).getByRole('checkbox', { name: /I acknowledge/ }))
    fireEvent.click(confirm)
    await waitFor(() => expect(preparations()).toHaveLength(2))
    expect(preparations()[1].args).toEqual({ action: 'delete_cloud', params: {
      providerId: provider.id, previewId: preview.previewId, acknowledgeDependencies: true,
    } })
    expect(calls.filter((call) => call.command === 'workspace_execute').map((call) => call.args))
      .toEqual([{ ticketId: 'ticket-preview_delete' }, { ticketId: 'ticket-delete_cloud' }])
  })
  it('cancels a deletion preview without preparing the destructive action', async () => {
    await restore()
    fireEvent.click(screen.getByRole('button', { name: 'Delete cloud backup' }))
    const dialog = await screen.findByRole('dialog', { name: 'Delete cloud backup' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(preparations().map((call) => call.args.action)).toEqual(['preview_delete'])
    expect(screen.queryByRole('dialog')).toBeNull()
  })
  it('does not reuse a preview after final native denial and never executes the denied action', async () => {
    await restore()
    fireEvent.click(screen.getByRole('button', { name: 'Delete cloud backup' }))
    const dialog = await screen.findByRole('dialog', { name: 'Delete cloud backup' })
    fireEvent.click(within(dialog).getByRole('checkbox', { name: /I acknowledge/ }))
    vi.mocked(invoke).mockRejectedValueOnce('Native deletion confirmation cancelled')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete with native confirmation' }))
    await screen.findByText('This preview has been submitted. Close and request a fresh preview before trying again.')
    const confirm = within(dialog).getByRole('button', { name: 'Delete with native confirmation' }) as HTMLButtonElement
    expect(confirm.disabled).toBe(true)
    fireEvent.click(confirm)
    expect(calls.filter((call) => call.command === 'workspace_execute')).toHaveLength(1)
  })
  it('rejects malformed dependency counts instead of bypassing separate acknowledgement', async () => {
    await restore()
    const original = vi.mocked(invoke).getMockImplementation()!
    vi.mocked(invoke).mockImplementation(async (command, args) => command === 'workspace_execute'
      ? { ...preview, dependentBundleCount: undefined } : original(command, args))
    fireEvent.click(screen.getByRole('button', { name: 'Delete cloud backup' }))
    await screen.findByRole('alert')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(preparations().map((call) => call.args.action)).toEqual(['preview_delete'])
  })
  it('disables upload and deletion for read-only providers but still permits download', async () => {
    nativeDashboard.providers[0].readOnly = true
    await restore()
    expect((screen.getByRole('button', { name: 'Delete cloud backup' }) as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByRole('button', { name: 'Download backup' }) as HTMLButtonElement).disabled).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Backup' }))
    expect((screen.getByRole('button', { name: 'Upload' }) as HTMLButtonElement).disabled).toBe(true)
  })
})

describe('frozen all-app and selected-app uploads', () => {
  it('previews the backend all-approved set even with no visible app rows, then uploads only the frozen ID', async () => {
    nativeDashboard.software = []
    nativeBatchPreview = { ...batchPreview, softwareCount: 41 }
    executeResult = { operationId: batchStatus.operationId, planSetId: batchPreview.planSetId }
    await backup()
    const scroll = document.querySelector('.main-scroll')!
    scroll.scrollTop = 180
    fireEvent.click(screen.getByRole('button', { name: 'Preview upload all' }))
    const dialog = await screen.findByRole('dialog', { name: 'Review batch upload' })
    expect(preparations().map((call) => call.args)).toEqual([
      { action: 'preview_upload_all', params: { providerId: provider.id } },
    ])
    expect(within(dialog).getByText('41 apps · All native-approved apps')).toBeTruthy()
    expect(within(dialog).getByText('File count unknown until native capture')).toBeTruthy()
    expect(within(dialog).getByText('Byte total unknown until native capture')).toBeTruthy()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Upload frozen app set' }))
    const region = await screen.findByRole('region', { name: 'Batch uploads' })
    await within(region).findByText('0 / 1 apps completed')
    expect(preparations()[1].args).toEqual({ action: 'upload_all', params: { planSetId: batchPreview.planSetId } })
    expect(calls.filter((call) => call.command === 'workspace_execute').map((call) => call.args)).toEqual([
      { ticketId: 'ticket-preview_upload_all' }, { ticketId: 'ticket-upload_all' },
    ])
    expect(calls.some((call) => call.args.query === 'batch_status')).toBe(true)
    expect(calls.some((call) => call.args.query === 'operation')).toBe(false)
    expect(open).not.toHaveBeenCalled()
    expect(scroll.scrollTop).toBe(180)
  })
  it('retains exact selected app identities across display pages without freezing the visible page as all apps', async () => {
    nativeDashboard.software = Array.from({ length: 21 }, (_, index) => ({
      ...software, id: `native-software-${index}`, name: `Native app ${index}`,
    }))
    nativeBatchPreview = { ...batchPreview, softwareCount: 2, selection: 'selected_apps' }
    await backup()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Include app Native app 0 in batch' }))
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Include app Native app 20 in batch' }))
    fireEvent.change(screen.getByLabelText('Find software'), { target: { value: 'no visible matches' } })
    fireEvent.click(screen.getByRole('button', { name: 'Preview selected apps (2)' }))
    const dialog = await screen.findByRole('dialog', { name: 'Review batch upload' })
    expect(preparations()[0].args).toEqual({ action: 'preview_upload_all', params: {
      providerId: provider.id, softwareIds: ['native-software-0', 'native-software-20'],
    } })
    expect(within(dialog).getByText('2 apps · Selected apps')).toBeTruthy()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(preparations()).toHaveLength(1)
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(calls.some((call) => call.args.action === 'upload_all')).toBe(false)
  })
  it('does not turn selected apps into a wildcard or the current filter when requesting upload all', async () => {
    nativeDashboard.software = Array.from({ length: 21 }, (_, index) => ({
      ...software, id: `native-software-${index}`, name: `Native app ${index}`,
    }))
    await backup()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Include app Native app 0 in batch' }))
    fireEvent.change(screen.getByLabelText('Find software'), { target: { value: 'Native app 20' } })
    fireEvent.click(screen.getByRole('button', { name: 'Preview upload all' }))
    await screen.findByRole('dialog', { name: 'Review batch upload' })
    expect(preparations()[0].args.params).toEqual({ providerId: provider.id })
    expect(JSON.stringify(preparations())).not.toContain('*')
  })
  it('never substitutes per-row uploads if the native all-app planner is unsupported', async () => {
    await backup()
    vi.mocked(invoke).mockRejectedValueOnce(new Error('Native frozen all-app planning is unavailable'))
    fireEvent.click(screen.getByRole('button', { name: 'Preview upload all' }))
    await screen.findByText('Native frozen all-app planning is unavailable')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(calls.some((call) => call.args.action === 'upload' || call.args.action === 'upload_all')).toBe(false)
    expect(calls.some((call) => call.command === 'workspace_execute')).toBe(false)
  })
  it('keeps batch upload disabled for imported read-only providers until the separate native write grant', async () => {
    nativeDashboard.providers[0] = { ...provider, readOnly: true, origin: 'noland' }
    await backup()
    fireEvent.change(screen.getByLabelText('Batch provider'), { target: { value: provider.id } })
    fireEvent.click(screen.getByRole('checkbox', { name: `Include app ${software.name} in batch` }))
    expect((screen.getByRole('button', { name: 'Preview upload all' }) as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByRole('button', { name: 'Preview selected apps (1)' }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText(/This connection is read-only/)).toBeTruthy()
    expect(preparations()).toHaveLength(0)
  })
  it('rejects a preview for another provider and never uploads a malformed or widened selection', async () => {
    nativeBatchPreview = { ...batchPreview, providerId: 'unapproved-provider' }
    await backup()
    fireEvent.click(screen.getByRole('button', { name: 'Preview upload all' }))
    await screen.findByText('The native batch belongs to a different provider.')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(preparations().map((call) => call.args.action)).toEqual(['preview_upload_all'])
  })
  it('does not reuse a frozen app plan after final native denial', async () => {
    await backup()
    fireEvent.click(screen.getByRole('button', { name: 'Preview upload all' }))
    const dialog = await screen.findByRole('dialog', { name: 'Review batch upload' })
    vi.mocked(invoke).mockRejectedValueOnce(new Error('Native batch approval denied'))
    fireEvent.click(within(dialog).getByRole('button', { name: 'Upload frozen app set' }))
    await within(dialog).findByText('This plan has been submitted. Close and create a fresh preview before trying again.')
    expect((within(dialog).getByRole('button', { name: 'Upload frozen app set' }) as HTMLButtonElement).disabled).toBe(true)
    expect(calls.filter((call) => call.command === 'workspace_execute')).toHaveLength(1)
    expect(screen.queryByRole('region', { name: 'Batch uploads' })).toBeNull()
  })
  it('uses only the native-returned original batch operation ID for explicit cancel and retry', async () => {
    executeResult = { operationId: batchStatus.operationId }
    const original = vi.mocked(invoke).getMockImplementation()!
    vi.mocked(invoke).mockImplementation(async (command, args) =>
      record(args)?.query === 'batch_status' ? { ...batchStatus, canRetry: true } : original(command, args))
    await backup()
    fireEvent.click(screen.getByRole('button', { name: 'Preview upload all' }))
    const dialog = await screen.findByRole('dialog', { name: 'Review batch upload' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Upload frozen app set' }))
    const region = await screen.findByRole('region', { name: 'Batch uploads' })
    await within(region).findByText('0 / 1 apps completed')
    fireEvent.click(within(region).getByText('App batch upload').closest('summary')!)
    fireEvent.click(within(region).getByRole('button', { name: 'Cancel original app batch' }))
    await waitFor(() => expect(preparations()).toHaveLength(3))
    expect(preparations()[2].args).toEqual({ action: 'cancel', params: { operationId: batchStatus.operationId } })
    await waitFor(() => expect((within(region).getByRole('button', { name: 'Retry original app batch' }) as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(within(region).getByRole('button', { name: 'Retry original app batch' }))
    await waitFor(() => expect(preparations()).toHaveLength(4))
    expect(preparations()[3].args).toEqual({ action: 'retry', params: { operationId: batchStatus.operationId } })
    expect(preparations().filter((call) => call.args.action === 'preview_upload_all')).toHaveLength(1)
    expect(calls.some((call) => call.args.query === 'software_files')).toBe(false)
  })
})

describe('rich native catalog history and pending deletions', () => {
  it('renders the actual Rust catalog fixture with explicit partial coverage, original instance, lineage and mode heads', async () => {
    const native = catalogBackendFixture()
    nativeDashboard.providers[0].id = 'fixture-provider'
    const original = vi.mocked(invoke).getMockImplementation()!
    vi.mocked(invoke).mockImplementation(async (command, args) =>
      record(args)?.query === 'bundles' ? native : original(command, args))
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Restore' }))
    fireEvent.click(screen.getByRole('button', { name: /Test drive drive/ }))
    await screen.findAllByRole('button', { name: /Original Game/ })
    fireEvent.click(screen.getAllByRole('button', { name: /Original Game/ })[0])
    expect(screen.getByText('Selected files only — not verified as a complete application.')).toBeTruthy()
    expect(screen.getByText(/Catalog observed:/)).toBeTruthy()
    fireEvent.click(screen.getByText('Restore options and backup details'))
    expect(screen.getByTitle('desktop:original')).toBeTruthy()
    expect(screen.getByTitle('00000000-0000-0000-0000-0000000001f5')).toBeTruthy()
    expect(screen.getByTitle('00000000-0000-0000-0000-000000000065')).toBeTruthy()
    expect(screen.getByText('Complete-mode head (not completeness proof)')).toBeTruthy()
    expect(screen.queryByText('Complete-application coverage')).toBeNull()
    expect(calls.some((call) => call.args.query === 'bundle_files')).toBe(false)
  })
  it('loads all generations for an exact app on demand and never filters just the current display page as full history', async () => {
    await restore()
    expect(calls.some((call) => call.args.query === 'history')).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'View app history' }))
    await screen.findByRole('heading', { name: `App history: ${bundle.name}` })
    await screen.findByRole('button', { name: new RegExp(bundle.name) })
    const history = calls.find((call) => call.args.query === 'history')
    expect(history?.args.params).toEqual({ providerId: provider.id, appId: bundle.appId, limit: 100 })
    fireEvent.click(screen.getByRole('button', { name: 'All backups' }))
    await waitFor(() => expect(calls.filter((call) => call.args.query === 'bundles')).toHaveLength(2))
    expect(preparations()).toHaveLength(0)
  })
  it('loads bounded pending-deletion summaries only when opened, preserving unknown dependencies without execution controls', async () => {
    const original = vi.mocked(invoke).getMockImplementation()!
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (record(args)?.query === 'pending_deletions') {
        calls.push({ command, args: structuredClone(args ?? {}) as Record<string, unknown> })
        return { pendingDeletions: [{
          planId: 'original-source-plan', names: ['Retained source backup'], nameCount: 99,
          detailsAvailable: false, dependenciesKnown: false, requiresNativePlanLoad: true,
        }] }
      }
      return original(command, args)
    })
    await restore()
    expect(calls.some((call) => call.args.query === 'pending_deletions')).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Show pending deletions' }))
    const region = await screen.findByRole('region', { name: 'Pending deletions' })
    fireEvent.click(await within(region).findByText('Plan original-source-plan'))
    expect(within(region).getByText('Unknown — load the authenticated native plan first')).toBeTruthy()
    expect(within(region).getByText('Showing 1 of 99 names.')).toBeTruthy()
    expect(within(region).getAllByTitle('original-source-plan')).toHaveLength(2)
    expect(calls.find((call) => call.args.query === 'pending_deletions')?.args.params).toEqual({ providerId: provider.id, limit: 100 })
    expect(within(region).queryByRole('button', { name: /Delete|Retry|Resume/ })).toBeNull()
    expect(preparations()).toHaveLength(0)
  })
  it('reports a stale revision cursor and refreshes from the first page instead of replaying the bad cursor', async () => {
    const original = vi.mocked(invoke).getMockImplementation()!
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (record(args)?.query === 'bundles') {
        calls.push({ command, args: structuredClone(args ?? {}) as Record<string, unknown> })
        if (record(record(args)?.params)?.cursor) throw new Error('Catalog cursor is stale; refresh from the first page')
        return { bundles: [bundle], nextCursor: 'revision-one-cursor' }
      }
      return original(command, args)
    })
    await restore()
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await screen.findByText('Catalog cursor is stale; refresh from the first page')
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await screen.findByRole('button', { name: new RegExp(bundle.name) })
    expect(calls.filter((call) => call.args.query === 'bundles').map((call) => record(call.args.params)?.cursor))
      .toEqual([undefined, 'revision-one-cursor', undefined])
  })
  it('shows native total restore conflicts separately from the bounded sample without pretending the preview is exhaustive', async () => {
    nativeRestorePreview = { ...restorePreview, conflictCount: 12_000, conflicts: [{ path: 'fixture.bin', reason: 'Existing file' }] }
    await restore()
    vi.mocked(open).mockResolvedValueOnce(paths.destination)
    fireEvent.click(screen.getByRole('button', { name: 'Download backup' }))
    const dialog = await screen.findByRole('dialog', { name: 'Review restore' })
    expect(within(dialog).getByText('Conflicts (12,000)')).toBeTruthy()
    expect(within(dialog).getByText('Showing 1 of 12,000 native conflicts. The frozen plan retains the complete inventory.')).toBeTruthy()
    expect(preparations().map((call) => call.args.action)).toEqual(['preview_restore'])
  })
  it('does not treat overwrite acknowledgement as authority to resolve native blocking conflicts', async () => {
    nativeRestorePreview = { ...restorePreview, conflictCount: 1, blockingConflicts: 1, requiresOverwriteAcknowledgement: true }
    await restore()
    vi.mocked(open).mockResolvedValueOnce(paths.destination)
    fireEvent.click(screen.getByRole('button', { name: 'Download backup' }))
    const dialog = await screen.findByRole('dialog', { name: 'Review restore' })
    fireEvent.click(within(dialog).getByRole('checkbox', { name: /I acknowledge overwriting/ }))
    expect((within(dialog).getByRole('button', { name: 'Restore with native confirmation' }) as HTMLButtonElement).disabled).toBe(true)
    expect(preparations().map((call) => call.args.action)).toEqual(['preview_restore'])
  })
})

describe('compact actual activity and scroll boundaries', () => {
  it('keeps activity details collapsed and shows only actual metrics without fake percentages', async () => {
    nativeDashboard.activity = [activity, { ...activity, id: 'connect-test', kind: 'connect', name: 'Test connection', completedBytes: undefined, totalBytes: undefined }]
    await ready()
    const section = screen.getByRole('region', { name: 'Activity' })
    expect(within(section).getByText('1 KB / 4 KB')).toBeTruthy()
    expect(section.textContent).not.toContain('%')
    expect(section.querySelector('details')?.open).toBe(false)
    expect(section.querySelectorAll('progress')).toHaveLength(1)
    expect(within(section).getByText('Test connection')).toBeTruthy()
  })
  it('offers restore recovery and retry only using native capability flags and the original operation ID', async () => {
    nativeDashboard.activity = [{
      ...activity, id: 'interrupted-restore', kind: 'download', name: 'Interrupted restore',
      state: 'interrupted', canCancel: false, canRetry: true, canRecover: true,
    }]
    await ready()
    const region = screen.getByRole('region', { name: 'Activity' })
    fireEvent.click(within(region).getByText('Interrupted restore').closest('summary')!)
    fireEvent.click(within(region).getByRole('button', { name: 'Recover original restore' }))
    await waitFor(() => expect(preparations()).toHaveLength(1))
    expect(preparations()[0].args).toEqual({ action: 'recover_restore', params: { operationId: 'interrupted-restore' } })
    await waitFor(() => expect((within(region).getByRole('button', { name: 'Retry original operation' }) as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(within(region).getByRole('button', { name: 'Retry original operation' }))
    await waitFor(() => expect(preparations()).toHaveLength(2))
    expect(preparations()[1].args).toEqual({ action: 'retry', params: { operationId: 'interrupted-restore' } })
    expect(open).not.toHaveBeenCalled()
  })
  it('does not invent cancellation, recovery or retry capabilities for a failed restore', async () => {
    nativeDashboard.activity = [{
      ...activity, kind: 'download', state: 'failed', canCancel: false, canRetry: false, canRecover: false,
      completedBytes: undefined, totalBytes: undefined, completedFiles: undefined, totalFiles: undefined,
    }]
    await ready()
    const region = screen.getByRole('region', { name: 'Activity' })
    expect(within(region).queryByRole('button', { name: /Cancel operation|Retry original operation|Recover original restore/ })).toBeNull()
    expect(region.querySelector('progress')).toBeNull()
  })
  it('defines one main scroll, stable modal gutters, ellipsis and readable mobile text', () => {
    const css = readFileSync(resolve(process.cwd(), 'src/styles.css'), 'utf8')
    expect(css).toMatch(/html, body, #root\s*\{[^}]*height: 100%[^}]*overflow: hidden/s)
    expect(css).toMatch(/\.main-scroll\s*\{[^}]*min-height: 0[^}]*overflow-y: auto[^}]*overflow-x: hidden[^}]*scrollbar-gutter: stable/s)
    expect(css).toMatch(/\.dialog-body\s*\{[^}]*min-height: 0[^}]*overflow-y: auto[^}]*scrollbar-gutter: stable/s)
    expect(css).toMatch(/\.truncate\s*\{[^}]*min-width: 0[^}]*text-overflow: ellipsis/s)
    expect(css).toContain('@media (max-width: 620px)')
    expect(css).not.toMatch(/min-width:\s*(360|880)px/)
    for (const match of css.matchAll(/font-size:\s*(\d+)px/g)) expect(Number(match[1])).toBeGreaterThanOrEqual(14)
  })
})
