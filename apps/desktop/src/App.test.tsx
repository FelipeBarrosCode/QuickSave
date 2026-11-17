import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { invoke, isTauri } from '@tauri-apps/api/core'
import { open } from '@tauri-apps/plugin-dialog'
import App from './App'
import { record } from './api'
import { capabilities, operation, paths, snapshot } from './test/fixtures'

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(), isTauri: vi.fn(() => true) }))
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn(), save: vi.fn() }))

let approvalSequence = 0
beforeEach(() => {
  approvalSequence = 0
  vi.mocked(isTauri).mockReturnValue(true)
  vi.mocked(invoke).mockImplementation(async (command) => {
    if (command === 'authorize_operation') return `test-native-approval-${++approvalSequence}`
    if (command === 'get_capabilities') return capabilities
    if (command === 'get_directories') return { data: '/isolated-test/data' }
    if (command === 'operation_history') return []
    if (command === 'list_snapshots') return { snapshots: [snapshot] }
    if (command === 'backup_folder') return operation
    if (command === 'restore_snapshot') return { ...operation, kind: 'restore' }
    if (command === 'operation_status') return { ...operation, state: 'completed' }
    throw new Error(`Unexpected test command: ${command}`)
  })
})
afterEach(cleanup)

async function prepareWorkspace() {
  render(<App />)
  await screen.findByText('Native backend connected')
  fireEvent.click(screen.getByRole('button', { name: 'Backups' }))
  for (const [name, path] of [
    ['Choose repository folder', paths.repository],
    ['Choose recovery-key file', paths.keyFile],
    ['Choose source folder', paths.source],
  ]) {
    vi.mocked(open).mockResolvedValueOnce(path)
    const button = screen.getByRole('button', { name })
    await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(button)
    await screen.findByDisplayValue(path)
  }
  fireEvent.click(screen.getByRole('button', { name: 'Open repository' }))
  await screen.findByText('Repository opened')
}

describe('desktop workflows', () => {
  it('shows an honest browser preview with no invoke calls or fake snapshot counts', () => {
    vi.mocked(isTauri).mockReturnValue(false)
    render(<App />)
    expect(screen.getByText('Preview only. Your files are not being backed up.')).toBeTruthy()
    expect(screen.queryByText(snapshot.snapshotId)).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Backups' }))
    expect((screen.getByRole('button', { name: 'Choose source folder' }) as HTMLButtonElement).disabled).toBe(true)
    expect(invoke).not.toHaveBeenCalled()
  })

  it('requires confirmation before invoking backup and keeps the native paths visible', async () => {
    await prepareWorkspace()
    fireEvent.click(screen.getByRole('button', { name: 'Back up this folder' }))
    const dialog = screen.getByRole('dialog', { name: 'Save a snapshot of this folder?' })
    expect(within(dialog).getByText(paths.source)).toBeTruthy()
    expect(within(dialog).getByText(paths.repository)).toBeTruthy()
    expect(within(dialog).getByText(/This preview grants no filesystem access/)).toBeTruthy()
    expect(vi.mocked(invoke).mock.calls.some(([name, args]) => name === 'authorize_operation' && record(args)?.kind === 'backup')).toBe(false)
    expect(vi.mocked(invoke).mock.calls.some(([name]) => name === 'backup_folder')).toBe(false)
    expect(document.activeElement).toBe(within(dialog).getByRole('button', { name: 'Cancel' }))
    const confirm = within(dialog).getByRole('button', { name: 'Start backup' })
    confirm.focus()
    fireEvent.keyDown(dialog, { key: 'Tab' })
    expect(document.activeElement).toBe(within(dialog).getByRole('button', { name: 'Close confirmation' }))
    fireEvent.keyDown(dialog, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(vi.mocked(invoke).mock.calls.some(([name]) => name === 'backup_folder')).toBe(false)
    expect(vi.mocked(invoke).mock.calls.some(([name, args]) => name === 'authorize_operation' && record(args)?.kind === 'backup')).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Back up this folder' }))
    fireEvent.click(screen.getByRole('button', { name: 'Start backup' }))
    await screen.findByText('Snapshot saved')
    expect(invoke).toHaveBeenCalledWith('backup_folder', {
      repository: paths.repository, source: paths.source, keyFile: paths.keyFile, approvalId: 'test-native-approval-2',
    })
    const backupIndex = vi.mocked(invoke).mock.calls.findIndex(([name]) => name === 'backup_folder')
    expect(vi.mocked(invoke).mock.calls[backupIndex - 1]).toEqual(['authorize_operation', {
      kind: 'backup', repository: paths.repository, source: paths.source, keyFile: paths.keyFile,
    }])
    expect(screen.queryByRole('progressbar')).toBeNull()
  })

  it('requires a selected snapshot, an empty-folder path and a restore confirmation', async () => {
    await prepareWorkspace()
    fireEvent.click(screen.getByRole('button', { name: 'Restore' }))
    const restore = screen.getByRole('button', { name: 'Restore selected snapshot' }) as HTMLButtonElement
    expect(restore.disabled).toBe(true)
    fireEvent.click(screen.getByRole('radio', { name: `Restore snapshot ${snapshot.snapshotId}` }))
    vi.mocked(open).mockResolvedValueOnce(paths.destination)
    fireEvent.click(screen.getByRole('button', { name: 'Choose empty destination folder' }))
    await screen.findByDisplayValue(paths.destination)
    await waitFor(() => expect(restore.disabled).toBe(false))
    fireEvent.click(restore)
    const dialog = screen.getByRole('dialog', { name: 'Restore this snapshot?' })
    expect(within(dialog).getByText(paths.destination)).toBeTruthy()
    expect(within(dialog).getByText(snapshot.snapshotId)).toBeTruthy()
    expect(vi.mocked(invoke).mock.calls.some(([name]) => name === 'restore_snapshot')).toBe(false)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(vi.mocked(invoke).mock.calls.some(([name]) => name === 'restore_snapshot')).toBe(false)
    vi.mocked(invoke)
      .mockResolvedValueOnce('test-restore-approval')
      .mockResolvedValueOnce({ ...operation, kind: 'restore' })
      .mockResolvedValueOnce({ ...operation, kind: 'restore', state: 'completed' })
    fireEvent.click(restore)
    fireEvent.click(screen.getByRole('button', { name: 'Restore to empty folder' }))
    await waitFor(() => expect(invoke).toHaveBeenCalledWith('restore_snapshot', {
      repository: paths.repository, keyFile: paths.keyFile,
      snapshotId: snapshot.snapshotId, destination: paths.destination, approvalId: 'test-restore-approval',
    }))
    const restoreIndex = vi.mocked(invoke).mock.calls.findIndex(([name]) => name === 'restore_snapshot')
    expect(vi.mocked(invoke).mock.calls[restoreIndex - 1]).toEqual(['authorize_operation', {
      kind: 'restore', repository: paths.repository, keyFile: paths.keyFile,
      snapshotId: snapshot.snapshotId, destination: paths.destination,
    }])
    await screen.findAllByText('Restore completed')
  })

  it('renders native error strings as text, not HTML', async () => {
    await prepareWorkspace()
    vi.mocked(invoke).mockRejectedValueOnce(new Error('<img src=x onerror=alert(1)>'))
    fireEvent.click(screen.getByRole('button', { name: 'Refresh snapshots' }))
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('<img src=x onerror=alert(1)>')
    expect(alert.querySelector('img')).toBeNull()
  })

  it('does not offer functional write controls when platform durability is unsupported', async () => {
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === 'get_capabilities') return {
        ...capabilities,
        localFolderBackups: false,
        platform: {
          platform: 'windows',
          filesystem: {
            ...capabilities.platform.filesystem,
            durable_create_new: false,
            windows_durable_write_status: 'unsupported: directory durability and private ACL creation are not implemented',
          },
        },
      }
      if (command === 'operation_history') return []
      if (command === 'get_directories') return {}
      return []
    })
    render(<App />)
    await screen.findByText('Repository creation, backup, and restore are currently disabled.')
    expect(screen.getByText(/unsupported: directory durability/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Backups' }))
    fireEvent.click(screen.getByRole('button', { name: 'Create new' }))
    expect((screen.getByRole('button', { name: 'Create repository' }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: 'Capabilities' }))
    expect(screen.getByText('Cloud providers & remote machines')).toBeTruthy()
    expect(screen.queryByRole('button', { name: /cloud|connect provider/i })).toBeNull()
  })

  it('does not start a backup when native confirmation is cancelled after the UI preview', async () => {
    await prepareWorkspace()
    vi.mocked(invoke).mockRejectedValueOnce(new Error('Native confirmation cancelled'))
    fireEvent.click(screen.getByRole('button', { name: 'Back up this folder' }))
    fireEvent.click(screen.getByRole('button', { name: 'Start backup' }))
    expect((await screen.findByRole('alert')).textContent).toContain('Native confirmation cancelled')
    expect(invoke).toHaveBeenLastCalledWith('authorize_operation', {
      kind: 'backup', repository: paths.repository, keyFile: paths.keyFile, source: paths.source,
    })
    expect(vi.mocked(invoke).mock.calls.some(([name]) => name === 'backup_folder')).toBe(false)
    expect(screen.queryByRole('region', { name: 'Native operation' })).toBeNull()
  })

  it.each([
    { name: 'blank', value: ' \t ' },
    { name: 'structured', value: { approvalId: 'not-raw' } },
    { name: 'oversized', value: 'not-to-be-displayed'.repeat(300) },
  ])('rejects a $name native approval without starting a backup', async ({ value }) => {
    await prepareWorkspace()
    vi.mocked(invoke).mockResolvedValueOnce(value)
    fireEvent.click(screen.getByRole('button', { name: 'Back up this folder' }))
    fireEvent.click(screen.getByRole('button', { name: 'Start backup' }))
    expect((await screen.findByRole('alert')).textContent).toContain('did not return a valid operation approval')
    expect(vi.mocked(invoke).mock.calls.some(([name]) => name === 'backup_folder')).toBe(false)
    expect(document.body.textContent).not.toContain('not-to-be-displayed')
    expect(document.body.textContent).not.toContain('not-raw')
  })

  it('does not reuse earlier native approval after the source scope changes', async () => {
    await prepareWorkspace()
    fireEvent.click(screen.getByRole('button', { name: 'Back up this folder' }))
    fireEvent.click(screen.getByRole('button', { name: 'Start backup' }))
    await screen.findByText('Snapshot saved')
    const picker = screen.getByRole('button', { name: 'Choose source folder' }) as HTMLButtonElement
    await waitFor(() => expect(picker.disabled).toBe(false))
    const changedSource = '/isolated-test/changed-source'
    vi.mocked(open).mockResolvedValueOnce(changedSource)
    fireEvent.click(picker)
    await screen.findByDisplayValue(changedSource)
    vi.mocked(invoke).mockRejectedValueOnce(new Error('Native approval for changed scope denied'))
    fireEvent.click(screen.getByRole('button', { name: 'Back up this folder' }))
    expect(within(screen.getByRole('dialog')).getByText(changedSource)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Start backup' }))
    expect((await screen.findByRole('alert')).textContent).toContain('changed scope denied')
    expect(invoke).toHaveBeenLastCalledWith('authorize_operation', {
      kind: 'backup', repository: paths.repository, keyFile: paths.keyFile, source: changedSource,
    })
    expect(vi.mocked(invoke).mock.calls.filter(([name]) => name === 'backup_folder')).toHaveLength(1)
    expect(vi.mocked(invoke).mock.calls.filter(([name, args]) =>
      name === 'authorize_operation' && record(args)?.kind === 'backup')).toHaveLength(2)
  })
})
