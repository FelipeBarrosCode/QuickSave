import { beforeEach, describe, expect, it, vi } from 'vitest'
import { invoke, isTauri } from '@tauri-apps/api/core'
import { open, save } from '@tauri-apps/plugin-dialog'
import {
  api, chooseFolder, chooseRecoveryKey, filesystemAvailability, normalizeHistory,
  normalizeOperation, normalizeSnapshots, operationId, safeError, terminal,
} from './api'
import { bytes, date, folderName } from './format'
import { capabilities, operation, paths, snapshot } from './test/fixtures'

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: vi.fn(() => true) }))
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: vi.fn() }))

let approvalSequence = 0
beforeEach(() => {
  approvalSequence = 0
  vi.mocked(isTauri).mockReturnValue(true)
  vi.mocked(invoke).mockImplementation(async (command) => {
    if (command === 'authorize_operation') return `test-native-approval-${++approvalSequence}`
    if (command === 'list_snapshots' || command === 'operation_history') return []
    if (command === 'operation_status') return operation
    return undefined
  })
})

describe('snapshot responses', () => {
  it('accepts a direct array and the documented snapshots envelope', () => {
    expect(normalizeSnapshots([snapshot])).toEqual([{
      id: snapshot.snapshotId, createdAt: snapshot.createdAt, totalFiles: 3, logicalBytes: 4096,
    }])
    expect(normalizeSnapshots({ snapshots: [{ id: 'alternate-id', files: 0, logicalBytes: 0 }] }))
      .toEqual([{ id: 'alternate-id', createdAt: null, totalFiles: 0, logicalBytes: 0 }])
  })

  it('sorts actual dates, without inventing missing dates or metadata', () => {
    const list = normalizeSnapshots([
      { id: 'old', createdAt: '2026-01-01T00:00:00Z', totalFiles: -1, logicalBytes: '1024' },
      snapshot,
      { id: 'unknown' },
    ])
    expect(list.map((item) => item.id)).toEqual([snapshot.snapshotId, 'old', 'unknown'])
    expect(list[1].totalFiles).toBeNull()
    expect(list[1].logicalBytes).toBeNull()
    expect(list[2].createdAt).toBeNull()
  })

  it('rejects malformed, duplicate, oversized and identifier-less results', () => {
    expect(() => normalizeSnapshots({ result: [] })).toThrow('invalid snapshot list')
    expect(() => normalizeSnapshots([{}])).toThrow('identifier')
    expect(() => normalizeSnapshots([{ id: 'same' }, { id: 'same' }])).toThrow('duplicate')
    expect(() => normalizeSnapshots([{ id: 'first', snapshotId: 'different' }])).toThrow('conflicting')
    expect(() => normalizeSnapshots(Array.from({ length: 10_001 }, () => snapshot))).toThrow('display limit')
    expect(() => normalizeSnapshots([{ id: 'a'.repeat(4_097) }])).toThrow('identifier')
  })
})

describe('native operation receipts', () => {
  it('normalizes completed and interrupted without conflating their outcomes', () => {
    const completed = normalizeOperation({ ...operation, state: 'completed' }, operation.id, 'backup')
    const interrupted = normalizeOperation({ ...operation, state: 'interrupted' }, operation.id, 'backup')
    expect(completed.state).toBe('succeeded')
    expect(interrupted.state).toBe('interrupted')
    expect(terminal(interrupted.state)).toBe(true)
    expect(terminal('running')).toBe(false)
    expect(operationId({ operationId: 'accepted-id' })).toBe('accepted-id')
    expect(operationId(operation)).toBe(operation.id)
  })

  it('rejects unexpected identities, kinds and states', () => {
    expect(() => normalizeOperation(operation, 'another-job', 'backup')).toThrow('identifier')
    expect(() => normalizeOperation(operation, operation.id, 'restore')).toThrow('kind')
    expect(() => normalizeOperation({ ...operation, state: 'maybe' }, operation.id, 'backup')).toThrow('state')
    expect(() => normalizeOperation({ ...operation, state: 'constructor' }, operation.id, 'backup')).toThrow('state')
    expect(() => operationId({})).toThrow('identifier')
  })

  it('bounds history and refuses multiple active jobs', () => {
    expect(normalizeHistory([{ ...operation, state: 'interrupted' }])[0].state).toBe('interrupted')
    expect(() => normalizeHistory([operation, { ...operation, id: 'second' }])).toThrow('more than one')
    expect(() => normalizeHistory([operation, operation])).toThrow('duplicate')
    expect(() => normalizeHistory([{ ...operation, kind: 'remote-delete' }])).toThrow('kind')
    expect(() => normalizeHistory(Array.from({ length: 1_025 }, () => operation))).toThrow('oversized')
  })
})

describe('native capabilities are fail-closed', () => {
  it('only enables writes after all required filesystem flags are confirmed', () => {
    expect(filesystemAvailability(null)).toMatchObject({ canRead: false, canWrite: false })
    expect(filesystemAvailability(capabilities)).toMatchObject({ canRead: true, canWrite: true, reason: null })
    expect(filesystemAvailability({ ...capabilities, localFolderBackups: false }).canWrite).toBe(false)
  })

  it('keeps Windows reads separate from explicitly unsupported durable writes', () => {
    const report = {
      ...capabilities,
      platform: {
        platform: 'windows',
        filesystem: {
          ...capabilities.platform.filesystem,
          durable_create_new: false,
          windows_durable_write_status: 'unsupported: private ACLs are not implemented',
        },
      },
    }
    expect(filesystemAvailability(report)).toEqual({
      canRead: true, canWrite: false, reason: 'unsupported: private ACLs are not implemented',
    })
  })
})

describe('exact Tauri invocation contract', () => {
  const repositoryPaths = { repository: paths.repository, keyFile: paths.keyFile }

  it('passes camelCase path arguments, never key contents', async () => {
    await api.initialize(repositoryPaths)
    await api.backup(repositoryPaths, paths.source)
    await api.restore(repositoryPaths, snapshot.snapshotId, paths.destination)
    expect(vi.mocked(invoke).mock.calls).toEqual([
      ['authorize_operation', { kind: 'initialize', ...repositoryPaths }],
      ['initialize_repository', { ...repositoryPaths, approvalId: 'test-native-approval-1' }],
      ['authorize_operation', { kind: 'backup', ...repositoryPaths, source: paths.source }],
      ['backup_folder', { ...repositoryPaths, source: paths.source, approvalId: 'test-native-approval-2' }],
      ['authorize_operation', { kind: 'restore', ...repositoryPaths, snapshotId: snapshot.snapshotId, destination: paths.destination }],
      ['restore_snapshot', { ...repositoryPaths, snapshotId: snapshot.snapshotId, destination: paths.destination, approvalId: 'test-native-approval-3' }],
    ])
  })

  it('uses operationId for status and normalizes the native result', async () => {
    vi.mocked(invoke).mockResolvedValue({ ...operation, state: 'completed' })
    expect((await api.status(operation.id, 'backup')).state).toBe('succeeded')
    expect(invoke).toHaveBeenCalledWith('operation_status', { operationId: operation.id })
    vi.mocked(invoke)
      .mockResolvedValueOnce('test-list-approval')
      .mockResolvedValueOnce({ snapshots: [snapshot] })
    expect((await api.snapshots(repositoryPaths))[0].id).toBe(snapshot.snapshotId)
    expect(vi.mocked(invoke).mock.calls.slice(-2)).toEqual([
      ['authorize_operation', { kind: 'list', ...repositoryPaths }],
      ['list_snapshots', { ...repositoryPaths, approvalId: 'test-list-approval' }],
    ])
  })

  it('refuses browser commands rather than returning fake data', async () => {
    vi.mocked(isTauri).mockReturnValue(false)
    await expect(api.backup(repositoryPaths, paths.source)).rejects.toThrow('desktop application')
    await expect(api.snapshots(repositoryPaths)).rejects.toThrow('desktop application')
    expect(invoke).not.toHaveBeenCalled()
  })

  it('uses native open/save paths without a filesystem or web upload fallback', async () => {
    vi.mocked(open).mockResolvedValueOnce(paths.source).mockResolvedValueOnce(paths.keyFile)
    vi.mocked(save).mockResolvedValue(paths.keyFile)
    expect(await chooseFolder('Choose source')).toBe(paths.source)
    expect(open).toHaveBeenNthCalledWith(1, { title: 'Choose source', directory: true, multiple: false })
    expect(await chooseRecoveryKey(false)).toBe(paths.keyFile)
    expect(open).toHaveBeenNthCalledWith(2, {
      title: 'Choose the external recovery-key file', directory: false, multiple: false,
    })
    expect(await chooseRecoveryKey(true)).toBe(paths.keyFile)
    expect(save).toHaveBeenCalledWith({
      title: 'Save a new external recovery-key file', defaultPath: 'quicksave-recovery.key',
    })
    expect(invoke).not.toHaveBeenCalled()
  })

  it('honors cancellation and refuses multi-selection responses', async () => {
    vi.mocked(open).mockResolvedValueOnce(null).mockResolvedValueOnce(['one', 'two'])
    expect(await chooseFolder('Choose source')).toBeNull()
    await expect(chooseFolder('Choose source')).rejects.toThrow('one folder')
  })
})

describe('per-request native authorization', () => {
  const repositoryPaths = { repository: paths.repository, keyFile: paths.keyFile }
  const requests = [
    {
      kind: 'initialize', command: 'initialize_repository', scope: repositoryPaths,
      run: () => api.initialize(repositoryPaths),
    },
    {
      kind: 'backup', command: 'backup_folder', scope: { ...repositoryPaths, source: paths.source },
      run: () => api.backup(repositoryPaths, paths.source),
    },
    {
      kind: 'list', command: 'list_snapshots', scope: repositoryPaths,
      run: () => api.snapshots(repositoryPaths),
    },
    {
      kind: 'restore', command: 'restore_snapshot',
      scope: { ...repositoryPaths, snapshotId: snapshot.snapshotId, destination: paths.destination },
      run: () => api.restore(repositoryPaths, snapshot.snapshotId, paths.destination),
    },
  ]

  it.each(requests)('requires exact native scope before $command', async ({ kind, command, scope, run }) => {
    await run()
    expect(vi.mocked(invoke).mock.calls).toEqual([
      ['authorize_operation', { kind, ...scope }],
      [command, { ...scope, approvalId: 'test-native-approval-1' }],
    ])
  })

  it.each(requests)('does not invoke $command when native confirmation is cancelled', async ({ kind, scope, run }) => {
    vi.mocked(invoke).mockRejectedValueOnce(new Error('Native authorization cancelled'))
    await expect(run()).rejects.toThrow('Native authorization cancelled')
    expect(vi.mocked(invoke).mock.calls).toEqual([['authorize_operation', { kind, ...scope }]])
  })

  it.each(requests)('rejects malformed approvals before $command without disclosing them', async ({ kind, scope, run }) => {
    const malformed = [
      null, undefined, false, 7, [], {}, { approvalId: 'not-a-raw-string' },
      '', ' \t\n ', '\u2003', 'x'.repeat(4_097), 'é'.repeat(2_049),
    ]
    for (const value of malformed) {
      vi.mocked(invoke).mockClear().mockResolvedValueOnce(value)
      await expect(run()).rejects.toThrow('The native backend did not return a valid operation approval.')
      expect(vi.mocked(invoke).mock.calls).toEqual([['authorize_operation', { kind, ...scope }]])
    }
  })

  it('awaits native confirmation without starting a filesystem command early', async () => {
    let approve!: (value: string) => void
    vi.mocked(invoke).mockImplementationOnce(() => new Promise((resolve) => { approve = resolve }))
    const request = api.backup(repositoryPaths, paths.source)
    expect(vi.mocked(invoke).mock.calls).toEqual([
      ['authorize_operation', { kind: 'backup', ...repositoryPaths, source: paths.source }],
    ])
    await Promise.resolve()
    expect(invoke).toHaveBeenCalledTimes(1)
    approve('deferred-native-approval')
    await request
    expect(invoke).toHaveBeenLastCalledWith('backup_folder', {
      ...repositoryPaths, source: paths.source, approvalId: 'deferred-native-approval',
    })
  })

  it('captures the approved scope before awaiting, despite caller mutation', async () => {
    let approve!: (value: string) => void
    vi.mocked(invoke).mockImplementationOnce(() => new Promise((resolve) => { approve = resolve }))
    const mutable = { ...repositoryPaths }
    const request = api.restore(mutable, snapshot.snapshotId, paths.destination)
    mutable.repository = '/isolated-test/different-repository'
    mutable.keyFile = '/isolated-test/different-recovery.key'
    approve('scope-pinned-approval')
    await request
    expect(vi.mocked(invoke).mock.calls).toEqual([
      ['authorize_operation', { kind: 'restore', ...repositoryPaths, snapshotId: snapshot.snapshotId, destination: paths.destination }],
      ['restore_snapshot', { ...repositoryPaths, snapshotId: snapshot.snapshotId, destination: paths.destination, approvalId: 'scope-pinned-approval' }],
    ])
  })

  it('ignores caller-injected approvals, kinds and unrelated scope fields', async () => {
    const injected = {
      ...repositoryPaths, approvalId: 'previously-consumed-token', kind: 'restore',
      source: '/isolated-test/unapproved-source', snapshotId: 'unapproved-snapshot',
      destination: '/isolated-test/unapproved-destination',
    }
    await api.snapshots(injected)
    expect(vi.mocked(invoke).mock.calls).toEqual([
      ['authorize_operation', { kind: 'list', ...repositoryPaths }],
      ['list_snapshots', { ...repositoryPaths, approvalId: 'test-native-approval-1' }],
    ])
  })

  it('does not reuse a list approval for a different operation or scope', async () => {
    await api.snapshots(repositoryPaths)
    vi.mocked(invoke).mockRejectedValueOnce(new Error('Native authorization denied for changed scope'))
    await expect(api.backup({
      repository: '/isolated-test/another-repository', keyFile: paths.keyFile,
    }, paths.source)).rejects.toThrow('denied for changed scope')
    expect(vi.mocked(invoke).mock.calls).toEqual([
      ['authorize_operation', { kind: 'list', ...repositoryPaths }],
      ['list_snapshots', { ...repositoryPaths, approvalId: 'test-native-approval-1' }],
      ['authorize_operation', {
        kind: 'backup', repository: '/isolated-test/another-repository',
        keyFile: paths.keyFile, source: paths.source,
      }],
    ])
  })

  it('does not retry a consumed approval after a filesystem rejection', async () => {
    vi.mocked(invoke)
      .mockResolvedValueOnce('first-single-use-approval')
      .mockRejectedValueOnce(new Error('Native scope proof changed'))
      .mockResolvedValueOnce('second-single-use-approval')
      .mockResolvedValueOnce(operation)
    await expect(api.backup(repositoryPaths, paths.source)).rejects.toThrow('scope proof changed')
    expect(invoke).toHaveBeenCalledTimes(2)
    await api.backup(repositoryPaths, paths.source)
    expect(vi.mocked(invoke).mock.calls).toEqual([
      ['authorize_operation', { kind: 'backup', ...repositoryPaths, source: paths.source }],
      ['backup_folder', { ...repositoryPaths, source: paths.source, approvalId: 'first-single-use-approval' }],
      ['authorize_operation', { kind: 'backup', ...repositoryPaths, source: paths.source }],
      ['backup_folder', { ...repositoryPaths, source: paths.source, approvalId: 'second-single-use-approval' }],
    ])
  })

  it('preserves an opaque bounded approval rather than trimming or parsing it', async () => {
    const token = ` opaque:${'x'.repeat(4_087)} `
    expect(token).toHaveLength(4_096)
    vi.mocked(invoke).mockResolvedValueOnce(token)
    await api.initialize(repositoryPaths)
    expect(invoke).toHaveBeenLastCalledWith('initialize_repository', { ...repositoryPaths, approvalId: token })
  })

  it('leaves passive capability, directory, history and status commands unchanged', async () => {
    await api.capabilities()
    await api.directories()
    await api.history()
    await api.status(operation.id, 'backup')
    expect(vi.mocked(invoke).mock.calls).toEqual([
      ['get_capabilities', undefined],
      ['get_directories', undefined],
      ['operation_history', undefined],
      ['operation_status', { operationId: operation.id }],
    ])
  })
})

describe('bounded text and honest formatting', () => {
  it('formats missing values without pretending they are zero', () => {
    expect(bytes(null)).toBe('—')
    expect(bytes(0)).toBe('0 B')
    expect(bytes(1024)).toBe('1 KB')
    expect(date(null)).toBe('Date not reported')
    expect(date('not-a-date')).toBe('Date not reported')
    expect(folderName('C:\\Users\\test\\Documents')).toBe('Documents')
    expect(folderName('/a/folder/')).toBe('folder')
  })

  it('bounds errors and does not stringify arbitrary native objects', () => {
    expect(safeError('a'.repeat(5_000))).toHaveLength(4_096)
    expect(safeError({ key: 'not-rendered' })).not.toContain('not-rendered')
    expect(safeError({ message: '<script>not executable</script>' })).toContain('<script>')
  })
})
