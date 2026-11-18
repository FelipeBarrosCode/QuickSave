import { beforeEach, describe, expect, it, vi } from 'vitest'
import { invoke, isTauri } from '@tauri-apps/api/core'
import { open, save } from '@tauri-apps/plugin-dialog'
import {
  api, chooseFiles, chooseFolder, chooseNoLandState, chooseRecoveryDestination, FILE_PAGE_SIZE, MAX_SELECTION,
  normalizeActivity, normalizeAppTracking, normalizeBatchStatus, normalizeBundles, normalizeDashboard, normalizeDeletePreview,
  normalizeFiles, normalizeNoLandDiscovery, normalizePendingDeletions, normalizeProviderTypes, normalizeRestorePreview,
  normalizeUploadBatchPreview, type ActionParams, type RestorePlan,
} from './api'
import { activity, appTracking, batchPreview, batchStatus, dashboard, files, importDiscovery, paths, preview, provider, providerTypes, respond, restorePreview, type Call } from './test/fixtures'

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: vi.fn(() => true) }))
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: vi.fn() }))
let calls: Call[]
beforeEach(() => {
  calls = []
  vi.mocked(isTauri).mockReturnValue(true)
  vi.mocked(invoke).mockImplementation(async (command, args) => {
    calls.push({ command, args: structuredClone(args ?? {}) as Record<string, unknown> })
    return respond(command, args as Record<string, unknown>)
  })
})

describe('workspace gateway and native consent', () => {
  it('queries only workspace_query with exact camelCase file scope and a bounded page', async () => {
    expect((await api.softwareFiles('software-test', 'cursor-test')).items).toEqual(files)
    expect(invoke).toHaveBeenCalledWith('workspace_query', {
      query: 'software_files', params: { softwareId: 'software-test', cursor: 'cursor-test', limit: FILE_PAGE_SIZE },
    })
    await api.bundleFiles('provider-test', 'bundle-test', 'app-test')
    expect(invoke).toHaveBeenLastCalledWith('workspace_query', {
      query: 'bundle_files', params: { providerId: 'provider-test', bundleId: 'bundle-test', appId: 'app-test', limit: 100 },
    })
  })
  it('prepares the exact captured subset and executes only its opaque ticket', async () => {
    let finish!: (value: unknown) => void
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      calls.push({ command, args: structuredClone(args ?? {}) as Record<string, unknown> })
      return command === 'workspace_prepare' ? new Promise((resolve) => { finish = resolve }) : dashboard
    })
    const params = { softwareId: 'software-test', providerId: provider.id, fileIds: [files[0].id] }
    const request = api.action('upload', params)
    params.fileIds.push('unapproved-file')
    params.providerId = 'unapproved-provider'
    finish({ ticketId: 'native-one-use-ticket' })
    await request
    expect(calls).toEqual([
      { command: 'workspace_prepare', args: { action: 'upload', params: {
        softwareId: 'software-test', providerId: provider.id, fileIds: [files[0].id],
      } } },
      { command: 'workspace_execute', args: { ticketId: 'native-one-use-ticket' } },
    ])
  })
  it('does not execute when native preparation is cancelled or unauthorized', async () => {
    vi.mocked(invoke).mockRejectedValueOnce(new Error('Native approval cancelled'))
    await expect(api.action('upload', { softwareId: 'test', providerId: 'test' })).rejects.toThrow('cancelled')
    expect(vi.mocked(invoke).mock.calls.map(([command]) => command)).toEqual(['workspace_prepare'])
  })
  it.each([null, {}, { ticketId: '' }, { ticketId: ' ' }, { ticketId: 'x'.repeat(4097) }, { ticketId: '🦔'.repeat(1500) }])(
    'rejects an invalid ticket without executing or exposing it: %#', async (response) => {
      vi.mocked(invoke).mockResolvedValueOnce(response)
      await expect(api.action('disconnect_provider', { providerId: provider.id })).rejects.toThrow()
      expect(vi.mocked(invoke).mock.calls).toHaveLength(1)
    },
  )
  it('never retries a used ticket after execution fails', async () => {
    vi.mocked(invoke).mockResolvedValueOnce({ ticketId: 'test-ticket' }).mockRejectedValueOnce('expired')
    await expect(api.action('cancel', { operationId: 'test-operation' })).rejects.toBe('expired')
    expect(vi.mocked(invoke).mock.calls).toHaveLength(2)
  })
  it('does not execute a ticket returned after the UI has abandoned pending consent', async () => {
    const controller = new AbortController()
    let finish!: (value: unknown) => void
    vi.mocked(invoke).mockImplementationOnce(() => new Promise((resolve) => { finish = resolve }))
    const pending = api.action('upload', { softwareId: 'test', providerId: 'test' }, controller.signal)
    controller.abort()
    finish({ ticketId: 'test-unused-ticket' })
    await expect(pending).rejects.toThrow('cancelled')
    expect(vi.mocked(invoke).mock.calls).toHaveLength(1)
  })
  it('uses fresh native consent for the separate provider-write grant', async () => {
    await api.action('authorize_provider_writes', { providerId: provider.id })
    expect(calls[0]).toEqual({
      command: 'workspace_prepare', args: { action: 'authorize_provider_writes', params: { providerId: provider.id } },
    })
    expect(calls[1].args).toEqual({ ticketId: 'test-ticket' })
  })
  it('prepares a provider-scoped read-only health check and executes only its ticket', async () => {
    await api.action('verify_provider', { providerId: provider.id })
    expect(calls).toEqual([
      { command: 'workspace_prepare', args: { action: 'verify_provider', params: { providerId: provider.id } } },
      { command: 'workspace_execute', args: { ticketId: 'test-ticket' } },
    ])
  })
  it('does not execute a provider health check after native consent is cancelled', async () => {
    vi.mocked(invoke).mockRejectedValueOnce(new Error('Native health-check confirmation cancelled'))
    await expect(api.action('verify_provider', { providerId: provider.id })).rejects.toThrow('cancelled')
    expect(vi.mocked(invoke).mock.calls.map(([command]) => command)).toEqual(['workspace_prepare'])
  })
  it('reads app tracking only through the native workspace query', async () => {
    expect(await api.appTracking()).toEqual(appTracking)
    expect(calls).toEqual([{ command: 'workspace_query', args: { query: 'app_tracking', params: {} } }])
  })
  it('uses a separate native consent pair for discovery and a discovered-source import', async () => {
    await api.action('discover_noland_import', {})
    await api.action('import_noland', { sourceId: importDiscovery.candidates[0].id })
    expect(calls).toEqual([
      { command: 'workspace_prepare', args: { action: 'discover_noland_import', params: {} } },
      { command: 'workspace_execute', args: { ticketId: 'test-ticket' } },
      { command: 'workspace_prepare', args: { action: 'import_noland', params: { sourceId: 'noland-source-test' } } },
      { command: 'workspace_execute', args: { ticketId: 'test-ticket' } },
    ])
    expect(open).not.toHaveBeenCalled()
  })
  it('captures a restore preview plan before consent and downloads only its opaque frozen preview ID', async () => {
    let finish!: (value: unknown) => void
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      calls.push({ command, args: structuredClone(args ?? {}) as Record<string, unknown> })
      return command === 'workspace_prepare' ? new Promise((resolve) => { finish = resolve }) : restorePreview
    })
    const plan: RestorePlan = {
      providerId: provider.id, bundleId: 'original-bundle', appId: 'original-app',
      destination: paths.destination, mode: 'replace', fileIds: [files[0].id],
    }
    const preparing = api.action('preview_restore', plan)
    plan.destination = '/isolated-test/unapproved'
    plan.mode = 'merge'
    plan.fileIds!.push('unapproved-file')
    finish({ ticketId: 'restore-plan-ticket' })
    await preparing
    expect(calls[0]).toEqual({ command: 'workspace_prepare', args: { action: 'preview_restore', params: {
      providerId: provider.id, bundleId: 'original-bundle', appId: 'original-app',
      destination: paths.destination, mode: 'replace', fileIds: [files[0].id],
    } } })
    const acknowledgement = { restorePreviewId: restorePreview.previewId, overwriteAcknowledgement: true }
    const downloading = api.action('download', acknowledgement)
    acknowledgement.overwriteAcknowledgement = false
    acknowledgement.restorePreviewId = 'unapproved-preview'
    finish({ ticketId: 'frozen-download-ticket' })
    await downloading
    expect(calls.slice(2)).toEqual([
      { command: 'workspace_prepare', args: { action: 'download', params: {
        restorePreviewId: restorePreview.previewId, overwriteAcknowledgement: true,
      } } },
      { command: 'workspace_execute', args: { ticketId: 'frozen-download-ticket' } },
    ])
  })
  it('rejects legacy direct downloads, missing acknowledgements and replacement restore paths before IPC', async () => {
    for (const input of [
      { providerId: provider.id, bundleId: 'test', appId: 'test', destination: paths.destination },
      { restorePreviewId: restorePreview.previewId },
      { restorePreviewId: restorePreview.previewId, overwriteAcknowledgement: 'true' },
      { restorePreviewId: restorePreview.previewId, overwriteAcknowledgement: true, destination: paths.destination },
    ]) {
      await expect(api.action('download', input as unknown as ActionParams['download'])).rejects.toThrow()
    }
    expect(invoke).not.toHaveBeenCalled()
  })
  it('bounds selected-file IDs and never turns an empty subset into a whole upload', async () => {
    for (const fileIds of [[], Array.from({ length: MAX_SELECTION + 1 }, (_, index) => `file-${index}`)]) {
      await expect(api.action('upload', { softwareId: 'test', providerId: 'test', fileIds })).rejects.toThrow('512')
    }
    expect(invoke).not.toHaveBeenCalled()
  })
  it('does not reflect native credential errors into the webview', async () => {
    vi.mocked(invoke).mockRejectedValueOnce(new Error('sensitive-credential-test-only'))
    await expect(api.action('connect_provider', {
      kind: 'test', name: 'test', credentials: { type: 'test', value: { password: 'sensitive-credential-test-only' } },
    })).rejects.not.toThrow('sensitive-credential')
  })
  it('reports unsupported native OAuth explicitly without echoing arbitrary error content', async () => {
    vi.mocked(invoke).mockRejectedValueOnce(new Error('Native OAuth with private handling is not available. test-private-secret'))
    await expect(api.action('connect_oauth', { kind: 'test', name: 'test', clientSecret: 'test-private-secret' }))
      .rejects.toThrow('Native OAuth is not available in this runtime. No account was connected.')
  })
  it('has no browser action, native picker, fake data, or browser-storage fallback', async () => {
    vi.mocked(isTauri).mockReturnValue(false)
    await expect(api.dashboard()).rejects.toThrow('desktop')
    await expect(api.action('import_noland', { stateFile: paths.stateFile })).rejects.toThrow('desktop')
    await expect(chooseFolder('Test picker')).rejects.toThrow('desktop')
    await expect(chooseFiles()).rejects.toThrow('desktop')
    await expect(chooseNoLandState()).rejects.toThrow('desktop')
    expect(invoke).not.toHaveBeenCalled()
    expect(open).not.toHaveBeenCalled()
  })
})

describe('bounded, sanitized workspace DTOs', () => {
  it('preserves native statuses and omits unexpected secret fields', () => {
    const parsed = normalizeDashboard({ ...dashboard, masterKey: 'should-not-be-in-webview', providers: [
      { ...provider, status: 'error', credentials: { password: 'test-only' } },
    ] })
    expect(parsed.providers[0].status).toBe('error')
    expect(JSON.stringify(parsed)).not.toContain('test-only')
    expect(JSON.stringify(parsed)).not.toContain('masterKey')
  })
  it('rejects missing safety-relevant statuses, booleans, counts, and duplicate IDs', () => {
    expect(() => normalizeDashboard({ ...dashboard, providers: [{ ...provider, status: 'ready' }] })).toThrow()
    expect(() => normalizeDashboard({ ...dashboard, software: [{ ...dashboard.software[0], autosave: 'true' }] })).toThrow()
    expect(() => normalizeDashboard({ ...dashboard, summary: { ...dashboard.summary, needsBackup: -1 } })).toThrow()
    expect(() => normalizeDashboard({ ...dashboard, providers: [provider, provider] })).toThrow('duplicate')
  })
  it('accepts only bounded file pages, so 186k entries cannot mount', () => {
    expect(() => normalizeFiles({ files: Array.from({ length: 186_000 }, () => files[0]) })).toThrow('bounded')
    expect(() => normalizeFiles({ files, nextCursor: {} })).toThrow()
    expect(() => normalizeFiles({ files: [{ ...files[0], size: -1 }] })).toThrow()
  })
  it('keeps missing bundle counts unknown and validates operation identity', async () => {
    expect(normalizeBundles({ bundles: [{
      id: 'test', appId: 'test', name: 'test', providerId: 'test',
    }] }).items[0].fileCount).toBeUndefined()
    vi.mocked(invoke).mockResolvedValueOnce(activity)
    await expect(api.operation('different-operation')).rejects.toThrow('does not match')
    expect(() => normalizeActivity({ ...activity, state: 'pretend_success' })).toThrow()
  })
  it('renders provider definitions dynamically and rejects undocumented auth', () => {
    expect(normalizeProviderTypes(providerTypes).map((type) => [type.kind, type.name, type.auth]))
      .toEqual([['drive', 'Google Drive', 'oauth'], ['onedrive', 'OneDrive', 'oauth'], ['s3', 'S3', 'credentials']])
    expect(() => normalizeProviderTypes([{ ...providerTypes[0], isOauth: 'browser-token' }])).toThrow()
  })
  it('requires a real frozen deletion preview and acknowledges reported dependencies', () => {
    expect(normalizeDeletePreview(preview).requiresDependencyAcknowledgement).toBe(true)
    expect(normalizeDeletePreview({ ...preview, dependentBundleCount: 0, dependentBundles: [] }).requiresDependencyAcknowledgement).toBe(false)
    expect(() => normalizeDeletePreview({ ...preview, providerId: 'another-provider' }, {
      providerId: provider.id, bundleId: preview.bundleId, appId: preview.appId,
    })).toThrow('different backup scope')
    expect(() => normalizeDeletePreview({ ...preview, dependentBundleCount: 0 })).toThrow('counts do not match')
    expect(() => normalizeDeletePreview({ files: 100 })).toThrow()
  })
  it('preserves only actual local roots, file roles and reported counts without inventing a file index', () => {
    const parsed = normalizeDashboard({
      ...dashboard,
      software: [{ ...dashboard.software[0], roots: [{
        id: 'actual-root', path: paths.root, roles: ['installation', 'runtime'],
        nativeProof: 'must-not-enter-webview',
      }], fileCount: undefined, logicalBytes: undefined }],
    })
    expect(parsed.software[0].fileCount).toBeUndefined()
    expect(parsed.software[0].logicalBytes).toBeUndefined()
    expect(parsed.software[0].roots).toEqual([{
      id: 'actual-root', path: paths.root, roles: ['installation', 'runtime'],
    }])
    expect(JSON.stringify(parsed)).not.toContain('nativeProof')
    expect(normalizeFiles({ files }).items.map((file) => file.role)).toEqual(['config', 'save'])
    expect(() => normalizeDashboard({
      ...dashboard, software: [{ ...dashboard.software[0], roots: [{ id: 'test', role: 'config' }] }],
    })).toThrow()
  })
  it('validates native tracking progress and bounded diagnostics without generating bundle rows', () => {
    const result = normalizeAppTracking({
      enabled: true, scanning: true, completedApps: 3, totalApps: 8,
      diagnostics: [{ appId: 'actual-app', code: 'missing_permission', message: 'Permission is missing.', secret: 'not-public' }],
    })
    expect(result.completedApps).toBe(3)
    expect(result.totalApps).toBe(8)
    expect(result.diagnostics).toHaveLength(1)
    expect(JSON.stringify(result)).not.toContain('not-public')
    expect(() => normalizeAppTracking({ ...appTracking, completedApps: 2, totalApps: 1 })).toThrow()
    expect(() => normalizeAppTracking({ ...appTracking, scanning: 'clock-progress' })).toThrow()
    expect(() => normalizeAppTracking({ ...appTracking, diagnostics: Array.from({ length: 257 }, () => ({ message: 'test' })) })).toThrow('bounded')
  })
  it('accepts bounded discovery candidates but never guesses a source from missing data', () => {
    expect(normalizeNoLandDiscovery(importDiscovery).candidates[0].id).toBe('noland-source-test')
    expect(normalizeNoLandDiscovery({ candidates: [] }).candidates).toEqual([])
    expect(() => normalizeNoLandDiscovery({ candidates: [], selectedId: 'invented-source' })).toThrow()
    expect(() => normalizeNoLandDiscovery({ candidates: [{ id: 'test', label: 'Missing path' }] })).toThrow()
    expect(() => normalizeNoLandDiscovery({ candidates: Array.from({ length: 65 }, (_, index) => ({
      id: `test-${index}`, label: 'Test', path: paths.stateFile,
    })) })).toThrow('bounded')
  })
  it('requires frozen restore counts, conflicts and an explicit native acknowledgement policy', () => {
    expect(normalizeRestorePreview(restorePreview)).toEqual(restorePreview)
    for (const invalid of [
      { ...restorePreview, previewId: undefined },
      { ...restorePreview, files: undefined },
      { ...restorePreview, bytes: -1 },
      { ...restorePreview, conflicts: undefined },
      { ...restorePreview, conflicts: [{ reason: 'Missing path' }] },
      { ...restorePreview, requiresOverwriteAcknowledgement: undefined },
      { ...restorePreview, requiresOverwriteAcknowledgement: 'true' },
    ]) expect(() => normalizeRestorePreview(invalid)).toThrow()
    expect(() => normalizeRestorePreview({
      ...restorePreview, conflicts: Array.from({ length: 257 }, () => ({ path: 'settings.json' })),
    })).toThrow('bounded')
  })
  it('rejects any mismatched native restore scope echo, including the selected file IDs', () => {
    const plan: RestorePlan = {
      providerId: provider.id, bundleId: 'test-bundle', appId: 'test-app',
      destination: paths.destination, mode: 'create_new', fileIds: [files[0].id],
    }
    for (const key of ['providerId', 'bundleId', 'appId', 'destination', 'mode'] as const) {
      expect(() => normalizeRestorePreview({ ...restorePreview, [key]: 'changed-scope' }, plan)).toThrow('different restore plan')
    }
    expect(() => normalizeRestorePreview({ ...restorePreview, fileIds: [files[1].id] }, plan)).toThrow('different file selection')
  })
  it('does not infer recovery or retry capability from operation kind, failure, or truthy text', () => {
    expect(normalizeActivity({ ...activity, kind: 'download', state: 'interrupted' }).canRecover).toBe(false)
    expect(normalizeActivity({ ...activity, canRecover: 'true', canRetry: 'true' }).canRecover).toBe(false)
    expect(normalizeActivity({ ...activity, canRecover: true }).canRecover).toBe(true)
  })
})

describe('frozen batch and catalog boundaries', () => {
  it('uses bounded on-demand history/pending pages and exact batch-status scope', async () => {
    await api.history(provider.id, 'app-test', 'native-history-cursor')
    await api.pendingDeletions(provider.id, 'native-pending-cursor')
    await api.batchStatus(batchPreview.planSetId, batchStatus.operationId)
    expect(calls.map((call) => call.args)).toEqual([
      { query: 'history', params: { providerId: provider.id, appId: 'app-test', cursor: 'native-history-cursor', limit: 100 } },
      { query: 'pending_deletions', params: { providerId: provider.id, cursor: 'native-pending-cursor', limit: 100 } },
      { query: 'batch_status', params: { planSetId: batchPreview.planSetId } },
    ])
  })
  it('requires a frozen plan ID for final batch execution, never a wildcard, replacement selection or JS authority flag', async () => {
    for (const input of [
      { planSetId: '*' }, { softwareIds: ['native-app'] }, { planSetId: 'native-plan', providerId: provider.id },
      { planSetId: 'native-plan', softwareIds: ['native-app'] }, { planSetId: 'native-plan', approved: true },
    ]) await expect(api.action('upload_all', input as unknown as ActionParams['upload_all'])).rejects.toThrow()
    expect(invoke).not.toHaveBeenCalled()
    await api.action('upload_all', { planSetId: batchPreview.planSetId })
    expect(calls[0].args).toEqual({ action: 'upload_all', params: { planSetId: batchPreview.planSetId } })
    expect(calls[1].args).toEqual({ ticketId: 'test-ticket' })
  })
  it('bounds selected apps without silently treating an empty or oversized selection as all apps', async () => {
    for (const softwareIds of [[], ['duplicate', 'duplicate'], ['*'], ['_all'],
      Array.from({ length: 513 }, (_, index) => `app-${index}`)]) {
      await expect(api.action('preview_upload_all', { providerId: provider.id, softwareIds })).rejects.toThrow('512')
    }
    expect(invoke).not.toHaveBeenCalled()
  })
  it('preserves native unknown batch file totals and rejects a preview for a different provider or selected-app count', () => {
    const result = normalizeUploadBatchPreview(batchPreview, { providerId: provider.id })
    expect(result.fileCount).toBeUndefined()
    expect(result.logicalBytes).toBeUndefined()
    expect(result.sampleNames).toEqual(batchPreview.sampleNames)
    expect(() => normalizeUploadBatchPreview(batchPreview, { providerId: 'other-provider' })).toThrow()
    expect(() => normalizeUploadBatchPreview(batchPreview, { providerId: provider.id, softwareIds: ['one', 'two'] })).toThrow()
    expect(() => normalizeUploadBatchPreview({ ...batchPreview, softwareCount: 0 }, { providerId: provider.id })).toThrow()
  })
  it('accepts real finalizing/unknown batch state without inventing percentages, totals or cancellation capability', () => {
    const status = normalizeBatchStatus({ ...batchStatus, state: 'unknown', canCancel: 'true' }, batchStatus.operationId)
    expect(status.state).toBe('unknown')
    expect(status.canCancel).toBe(false)
    expect(status.progress[0].total).toBeUndefined()
    expect(() => normalizeBatchStatus(batchStatus, 'different-operation')).toThrow('identifier')
    expect(() => normalizeBatchStatus({ ...batchStatus, childCount: 5000 }, batchStatus.operationId)).toThrow('bounded')
    expect(() => normalizeBatchStatus({ ...batchStatus, completed: 2 }, batchStatus.operationId)).toThrow('counts')
  })
  it('keeps legacy catalog counts, coverage and freshness unknown, and accepts the actual 8192-byte cursor bound', () => {
    const parsed = normalizeBundles({ bundles: [{
      id: 'actual-bundle', appId: 'actual-app', providerId: provider.id, name: 'Actual backup',
      mode: 'complete_application',
    }], nextCursor: 'a'.repeat(8192) })
    expect(parsed.items[0].completeness).toBeUndefined()
    expect(parsed.items[0].completeApplication).toBeUndefined()
    expect(parsed.items[0].fileCount).toBeUndefined()
    expect(parsed.freshness).toBeUndefined()
    expect(parsed.nextCursor).toHaveLength(8192)
    expect(() => normalizeBundles({ bundles: [], nextCursor: 'a'.repeat(8193) })).toThrow('cursor')
  })
  it('refuses to display a catalog page as execution authority or accept another app/provider history', () => {
    const row = { id: 'real-bundle', appId: 'real-app', providerId: provider.id, name: 'Real backup' }
    expect(() => normalizeBundles({ bundles: [row], authoritativeForExecution: true })).toThrow('authorize')
    expect(() => normalizeBundles({ bundles: [row] }, 'other-provider')).toThrow('different')
    expect(() => normalizeBundles({ bundles: [row] }, provider.id, 'other-app')).toThrow('different')
  })
  it('does not invent pending deletion dependencies from names, ordering or requested counts', () => {
    const page = normalizePendingDeletions({ pendingDeletions: [{
      planId: 'native-pending-plan', names: ['Retained backup'], detailsAvailable: false,
      requiresNativePlanLoad: true, dependenciesKnown: false, nameCount: 4,
    }] })
    expect(page.items[0].dependentCount).toBeUndefined()
    expect(page.items[0].affectedCount).toBeUndefined()
    expect(() => normalizePendingDeletions({ pendingDeletions: [{ ...page.items[0], dependenciesKnown: true }] })).toThrow('count')
    expect(() => normalizePendingDeletions({ pendingDeletions: [page.items[0], page.items[0]] })).toThrow('duplicate')
  })
})

describe('existing provider reauthorization and recovery export privacy', () => {
  it('uses native tickets for OAuth reauthorization without replacing client configuration or providing tokens', async () => {
    await api.action('reauthorize_provider', { providerId: provider.id })
    expect(calls).toEqual([
      { command: 'workspace_prepare', args: { action: 'reauthorize_provider', params: { providerId: provider.id } } },
      { command: 'workspace_execute', args: { ticketId: 'test-ticket' } },
    ])
  })
  it('refuses routing/client/root mutation fields before IPC for an existing provider', async () => {
    for (const extra of [{ kind: 'other-kind' }, { clientId: 'other-client' }, { bucket: 'other-bucket' },
      { prefix: 'other-folder' }, { root: '/isolated-test/other-root' }]) {
      await expect(api.action('reauthorize_provider', {
        providerId: provider.id, ...extra,
      } as unknown as ActionParams['reauthorize_provider'])).rejects.toThrow('cannot change')
    }
    expect(invoke).not.toHaveBeenCalled()
  })
  it('clears credentials after capture and suppresses secret-bearing native reauthorization errors', async () => {
    vi.mocked(invoke).mockRejectedValueOnce(new Error('backend echoed synthetic-new-secret'))
    await expect(api.action('reauthorize_provider', {
      providerId: provider.id, credentials: { type: 's3', value: { secret_access_key: 'synthetic-new-secret' } },
    })).rejects.not.toThrow('synthetic-new-secret')
    expect(calls.filter((call) => call.command === 'workspace_execute')).toHaveLength(0)
  })
  it('exports only an exact provider/destination plan with native confirmation, never JS overwrite or key bytes', async () => {
    await api.action('export_recovery_key', { providerId: provider.id, destination: '/isolated-test/external/recovery.key' })
    expect(calls[0].args).toEqual({ action: 'export_recovery_key', params: {
      providerId: provider.id, destination: '/isolated-test/external/recovery.key',
    } })
    expect(calls[1].args).toEqual({ ticketId: 'test-ticket' })
    await expect(api.action('export_recovery_key', {
      providerId: provider.id, destination: '/isolated-test/external/recovery.key', overwrite: true,
    } as unknown as ActionParams['export_recovery_key'])).rejects.toThrow('only')
    expect(calls).toHaveLength(2)
  })
})

describe('native file pickers', () => {
  it('uses a native Save dialog for a new external recovery-key file, never reading key bytes', async () => {
    vi.mocked(save).mockResolvedValueOnce('/isolated-test/external/fixture-recovery.key')
    expect(await chooseRecoveryDestination()).toBe('/isolated-test/external/fixture-recovery.key')
    expect(save).toHaveBeenCalledWith({
      title: 'Export recovery key to a new external private file', defaultPath: 'QuickSave-recovery.key',
      filters: [{ name: 'Recovery key', extensions: ['key'] }],
    })
    expect(invoke).not.toHaveBeenCalled()
  })
  it('does not accept a relative recovery-key destination or synthesize a path after Save cancellation', async () => {
    vi.mocked(save).mockResolvedValueOnce(null).mockResolvedValueOnce('relative/recovery.key')
    expect(await chooseRecoveryDestination()).toBeNull()
    await expect(chooseRecoveryDestination()).rejects.toThrow('absolute')
    expect(invoke).not.toHaveBeenCalled()
  })
  it('selects JSON state without reading its contents and leaves final consent to the gateway', async () => {
    vi.mocked(open).mockResolvedValueOnce(paths.stateFile)
    expect(await chooseNoLandState()).toBe(paths.stateFile)
    expect(open).toHaveBeenCalledWith({
      title: 'Choose No Land state.json', directory: false, multiple: false,
      filters: [{ name: 'JSON state', extensions: ['json'] }],
    })
    expect(invoke).not.toHaveBeenCalled()
  })
  it('cancels cleanly and rejects relative or multiple state-file paths', async () => {
    vi.mocked(open).mockResolvedValueOnce(null).mockResolvedValueOnce('relative/state.json').mockResolvedValueOnce([paths.stateFile])
    expect(await chooseNoLandState()).toBeNull()
    await expect(chooseNoLandState()).rejects.toThrow('absolute')
    await expect(chooseNoLandState()).rejects.toThrow()
  })
  it('bounds manual selections and uses the directory/file picker modes', async () => {
    vi.mocked(open).mockResolvedValueOnce(paths.root).mockResolvedValueOnce([paths.file])
    expect(await chooseFolder('Test folder')).toBe(paths.root)
    expect(await chooseFiles()).toEqual([paths.file])
    expect(open).toHaveBeenNthCalledWith(1, { title: 'Test folder', directory: true, multiple: false })
    expect(open).toHaveBeenNthCalledWith(2, { title: 'Add files to QuickSave', directory: false, multiple: true })
    vi.mocked(open).mockResolvedValueOnce(Array.from({ length: 513 }, () => paths.file))
    await expect(chooseFiles()).rejects.toThrow('512')
  })
})
