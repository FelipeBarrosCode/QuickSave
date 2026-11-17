// SPDX-License-Identifier: GPL-3.0-only
// The webview handles native paths only. Recovery-key bytes stay in Rust.
import { invoke, isTauri } from '@tauri-apps/api/core'
import { open, save } from '@tauri-apps/plugin-dialog'

export type NativeReport = Record<string, unknown>
export type OperationKind = 'initialize' | 'backup' | 'restore'
export type OperationState = 'queued' | 'running' | 'succeeded' | 'failed' | 'interrupted'

export interface Snapshot {
  id: string
  createdAt: string | null
  totalFiles: number | null
  logicalBytes: number | null
}

export interface Operation {
  id: string
  kind: OperationKind
  state: OperationState
  startedAt: string | null
  finishedAt: string | null
  result: unknown
  error: string | null
}

export interface RepositoryPaths {
  repository: string
  keyFile: string
}

const MAX_SNAPSHOTS = 10_000
const MAX_TEXT = 4_096
const MAX_APPROVAL_BYTES = 4_096

export const nativeRuntime = () => isTauri()

export function record(value: unknown): NativeReport | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as NativeReport)
    : null
}

export function safeError(value: unknown): string {
  if (value instanceof Error) return value.message.slice(0, MAX_TEXT)
  if (typeof value === 'string') return value.slice(0, MAX_TEXT)
  const object = record(value)
  if (typeof object?.message === 'string') return object.message.slice(0, MAX_TEXT)
  return 'The native operation could not be completed. Check your paths and try again.'
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_TEXT
    ? value
    : null
}

function count(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
    ? value
    : null
}

export function normalizeSnapshots(value: unknown): Snapshot[] {
  const entries = Array.isArray(value) ? value : record(value)?.snapshots
  if (!Array.isArray(entries)) throw new Error('The backend returned an invalid snapshot list.')
  if (entries.length > MAX_SNAPSHOTS) {
    throw new Error('This snapshot list exceeds the desktop display limit (10,000).')
  }
  const seen = new Set<string>()
  return entries.map((entry) => {
    const item = record(entry)
    const snapshotId = text(item?.snapshotId)
    const alternateId = text(item?.id)
    if (snapshotId && alternateId && snapshotId !== alternateId) {
      throw new Error('The backend returned conflicting snapshot identifiers.')
    }
    const id = snapshotId ?? alternateId
    if (!item || !id || seen.has(id)) {
      throw new Error('The backend returned a missing or duplicate snapshot identifier.')
    }
    seen.add(id)
    return {
      id,
      createdAt: text(item.createdAt),
      totalFiles: count(item.totalFiles) ?? count(item.files),
      logicalBytes: count(item.logicalBytes),
    }
  }).sort((a, b) => {
    const left = a.createdAt ? Date.parse(a.createdAt) : 0
    const right = b.createdAt ? Date.parse(b.createdAt) : 0
    return (Number.isFinite(right) ? right : 0) - (Number.isFinite(left) ? left : 0)
  })
}

export function operationId(value: unknown): string {
  const summary = record(value)
  const id = text(summary?.operationId) ?? text(summary?.id)
  if (!id) throw new Error('The native backend did not return an operation identifier.')
  return id
}

export function normalizeOperation(value: unknown, expectedId: string, kind: OperationKind): Operation {
  const item = record(value)
  if (!item || text(item.id) !== expectedId) {
    throw new Error('The backend returned a different or invalid operation identifier.')
  }
  if (item.kind !== kind) throw new Error('The backend returned a different operation kind.')
  const states: Record<string, OperationState> = {
    queued: 'queued',
    pending: 'queued',
    running: 'running',
    succeeded: 'succeeded',
    success: 'succeeded',
    completed: 'succeeded',
    failed: 'failed',
    interrupted: 'interrupted',
  }
  const state = typeof item.state === 'string' && Object.prototype.hasOwnProperty.call(states, item.state)
    ? states[item.state] : undefined
  if (!state) throw new Error('The backend returned an unsupported operation state.')
  return {
    id: expectedId,
    kind,
    state,
    startedAt: text(item.startedAt),
    finishedAt: text(item.finishedAt),
    result: item.result ?? null,
    error: item.error == null ? null : safeError(item.error),
  }
}

export function normalizeHistory(value: unknown): Operation[] {
  if (!Array.isArray(value) || value.length > 1_024) {
    throw new Error('The backend returned an invalid or oversized operation history.')
  }
  const seen = new Set<string>()
  const operations = value.map((entry) => {
    const item = record(entry)
    const id = operationId(entry)
    if (seen.has(id)) throw new Error('The backend returned duplicate operation identifiers.')
    seen.add(id)
    if (item?.kind !== 'initialize' && item?.kind !== 'backup' && item?.kind !== 'restore') {
      throw new Error('The backend returned an unsupported operation kind.')
    }
    return normalizeOperation(entry, id, item.kind)
  })
  if (operations.filter((operation) => !terminal(operation.state)).length > 1) {
    throw new Error('The backend reported more than one active operation. Native mutations are disabled.')
  }
  return operations.sort((a, b) => (b.startedAt ?? '').localeCompare(a.startedAt ?? ''))
}

export function filesystemAvailability(report: NativeReport | null): { canRead: boolean; canWrite: boolean; reason: string | null } {
  const platform = record(report?.platform)
  const filesystem = record(platform?.filesystem)
  const canRead = filesystem?.native_directory_handles === true && filesystem.handle_anchored_reads === true
  const canWrite = canRead && report?.localFolderBackups === true
    && filesystem?.durable_create_new === true
    && filesystem.durable_directory_creation === true
    && filesystem.private_directory_creation === true
  const reason = canWrite ? null
    : platform?.platform === 'windows' && typeof filesystem?.windows_durable_write_status === 'string'
      ? filesystem.windows_durable_write_status
      : report ? 'The native report has not confirmed safe, durable local filesystem writes. Backup, restore, and repository creation are disabled.'
        : 'A native platform report is required before filesystem operations can be enabled.'
  return { canRead, canWrite, reason }
}

async function command<T>(name: string, args?: Record<string, unknown>): Promise<T> {
  if (!nativeRuntime()) {
    throw new Error('Native actions are available only in the QuickSave desktop application.')
  }
  return invoke<T>(name, args)
}

type AuthorizationScope =
  | (RepositoryPaths & { kind: 'initialize' | 'list' })
  | (RepositoryPaths & { kind: 'backup'; source: string })
  | (RepositoryPaths & { kind: 'restore'; snapshotId: string; destination: string })

const filesystemCommands = {
  initialize: 'initialize_repository',
  backup: 'backup_folder',
  list: 'list_snapshots',
  restore: 'restore_snapshot',
} as const

async function authorizedCommand(scope: AuthorizationScope): Promise<unknown> {
  // Capture only this wrapper's explicit fields before awaiting native consent.
  // Neither caller mutations nor caller-supplied approvals may alter that scope.
  const captured = Object.freeze({ ...scope })
  const { kind, ...paths } = captured
  const approvalId = await command<unknown>('authorize_operation', captured)
  if (typeof approvalId !== 'string' || approvalId.length === 0
    || approvalId.length > MAX_APPROVAL_BYTES || approvalId.trim().length === 0
    || new TextEncoder().encode(approvalId).byteLength > MAX_APPROVAL_BYTES) {
    // Never echo an invalid opaque approval into the UI, logs, or operation history.
    throw new Error('The native backend did not return a valid operation approval.')
  }
  // Approval stays local to this call and is consumed once, without caching or retry.
  // Rust owns confirmation, expiry, single use, root proofs, and scope enforcement.
  return command<unknown>(filesystemCommands[kind], { ...paths, approvalId })
}

export const api = {
  capabilities: () => command<NativeReport>('get_capabilities'),
  directories: () => command<NativeReport>('get_directories'),
  history: async () => normalizeHistory(await command<unknown>('operation_history')),
  initialize: (paths: RepositoryPaths) =>
    authorizedCommand({ kind: 'initialize', repository: paths.repository, keyFile: paths.keyFile }),
  backup: (paths: RepositoryPaths, source: string) =>
    authorizedCommand({ kind: 'backup', repository: paths.repository, keyFile: paths.keyFile, source }),
  snapshots: async (paths: RepositoryPaths) =>
    normalizeSnapshots(await authorizedCommand({ kind: 'list', repository: paths.repository, keyFile: paths.keyFile })),
  restore: (paths: RepositoryPaths, snapshotId: string, destination: string) =>
    authorizedCommand({ kind: 'restore', repository: paths.repository, keyFile: paths.keyFile, snapshotId, destination }),
  status: async (id: string, kind: OperationKind) =>
    normalizeOperation(await command<unknown>('operation_status', { operationId: id }), id, kind),
}

export async function chooseFolder(title: string): Promise<string | null> {
  if (!nativeRuntime()) throw new Error('Open QuickSave desktop to choose a native folder.')
  const selected = await open({ title, directory: true, multiple: false })
  if (selected === null) return null
  if (typeof selected !== 'string') throw new Error('Select one folder at a time.')
  return selected
}

export async function chooseRecoveryKey(create: boolean): Promise<string | null> {
  if (!nativeRuntime()) throw new Error('Open QuickSave desktop to choose a recovery-key path.')
  const selected = create
    ? await save({ title: 'Save a new external recovery-key file', defaultPath: 'quicksave-recovery.key' })
    : await open({ title: 'Choose the external recovery-key file', directory: false, multiple: false })
  if (selected === null) return null
  if (typeof selected !== 'string') throw new Error('Select one recovery-key file at a time.')
  return selected
}

export function terminal(state: OperationState): boolean {
  return state === 'succeeded' || state === 'failed' || state === 'interrupted'
}
