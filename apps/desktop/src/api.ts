// SPDX-License-Identifier: GPL-3.0-only
// Only sanitized workspace metadata and transient provider inputs enter the webview.
import { invoke, isTauri } from '@tauri-apps/api/core'
import { open, save } from '@tauri-apps/plugin-dialog'

export type Provider = {
  id: string; name: string; kind: string
  status: 'connected' | 'connecting' | 'disconnected' | 'error'
  origin?: 'quicksave' | 'noland'; readOnly?: boolean; error?: string | null
}
export type Software = {
  id: string; appId?: string; name: string; tracked: boolean; providerId?: string | null
  status: 'needs_backup' | 'saved' | 'checking' | 'uploading' | 'error' | 'not_tracked'
  autosave: boolean; dirty?: boolean; lastSavedAt?: string | null
  fileCount?: number | null; logicalBytes?: number | null; error?: string | null
  roots?: SoftwareRoot[]
}
export type SoftwareRoot = {
  id: string; path: string; role?: string; roles?: string[]
  fileCount?: number; logicalBytes?: number
}
export type TrackingRole = 'installation' | 'save' | 'config' | 'runtime'
export type TrackingDiagnostic = {
  appId?: string; name?: string; code?: string; message: string; path?: string
}
export type AppTracking = {
  enabled: boolean; scanning: boolean; completedApps: number; totalApps: number
  diagnostics: TrackingDiagnostic[]
}
export type NoLandSource = {
  id: string; label: string; path: string; modifiedAt?: string; profileCount?: number
}
export type NoLandDiscovery = { candidates: NoLandSource[]; selectedId?: string }
export type CaptureCoverage = 'unknown' | 'selected_files' | 'approved_software' | 'personal_state' | 'complete_application'
export type BackupMode = 'complete_application' | 'personal_state' | 'custom'
export type BundleReadiness = {
  metadataVerified: boolean; filesAvailable: boolean; applicationReady: boolean
  requiresNativeRestorePreview: boolean
}
export type Bundle = {
  id: string; appId: string; name: string; providerId: string
  createdAt?: string | null; fileCount?: number | null; logicalBytes?: number | null
  platform?: string | null; format?: string; compatibility?: string
  sourceBundleId?: string; sourceAppId?: string
  commitId?: string; parentBundleId?: string | null; sourceInstanceId?: string
  mode?: BackupMode; completeness?: CaptureCoverage; captureScopeLabel?: string
  storedIncrementalBytes?: number; tombstoneCount?: number
  completeApplication?: boolean; subset?: boolean | null; readiness?: BundleReadiness
  currentHead?: boolean; currentCompleteHead?: boolean; currentPersonalStateHead?: boolean
}
export type CatalogFreshness = {
  source?: string; refreshStartedAt?: string; observedAt?: string; coalesced: boolean
}
export type CatalogPage<T> = PageResult<T> & {
  providerId?: string; revision?: string; catalogCommitId?: string
  freshness?: CatalogFreshness; authoritativeForExecution?: false
}
export type PendingDeletion = {
  planId: string; operationId?: string; digest?: string; names: string[]; nameCount?: number
  detailsAvailable: boolean; requiresNativePlanLoad: boolean; dependenciesKnown: boolean
  requestedCount?: number; affectedCount?: number; dependentCount?: number
  logicalBytes?: number; physicalBytes?: number; packCount?: number; metadataObjectCount?: number
}
export type UploadBatchPlan = {
  providerId: string; softwareIds?: string[]
}
export type UploadBatchPreview = {
  planSetId: string; providerId: string; softwareCount: number; summary?: string
  sampleNames?: string[]; jobCount?: number; fileCount?: number; logicalBytes?: number
  createdAt?: string; selection?: 'all_approved_apps' | 'selected_apps'
  fileCapture?: string; selectionFrozen?: string
}
export type BatchState = Activity['state'] | 'finalizing' | 'unknown'
export type BatchStatus = {
  operationId: string; state: BatchState; jobCount?: number; childCount?: number
  completed?: number; failed?: number; cancelled?: number; interrupted?: number
  active?: number; notStarted?: number; unknown?: number; awaitingFinalization?: number
  cancelRequested?: boolean; canRetry: boolean; canCancel: boolean; shutdownBlocked?: boolean
  progress: { phase: string; unit: string; completed: number; total?: number; reportingChildren: number }[]
}
export type BatchReference = {
  planSetId: string; operationId: string; providerId?: string; softwareCount?: number
}
export type FileItem = {
  id: string; name: string; path: string; directory: boolean; size: number
  status?: string; rootId?: string; role?: string
}
export type Activity = {
  id: string; kind: 'upload' | 'download' | 'delete' | 'connect' | 'autosave'
  name: string; providerId?: string; softwareId?: string
  planSetId?: string
  state: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'interrupted'
  phase?: string; completedBytes?: number; totalBytes?: number
  completedFiles?: number; totalFiles?: number; error?: string | null
  canCancel?: boolean; canRetry?: boolean; canRecover?: boolean
  startedAt?: string; finishedAt?: string | null
}
export type Dashboard = {
  providers: Provider[]; software: Software[]; activity: Activity[]
  activityUnavailable?: boolean; activityIssue?: string
  summary: { needsBackup: number; autosaveEnabled: number; connectedProviders: number }
}
export type ProviderField = {
  name: string; label: string; required: boolean; secret: boolean; credential: boolean
  type: 'text' | 'password' | 'select' | 'number' | 'toggle'; options?: { value: string; label: string }[]
}
export type ProviderType = {
  kind: string; name: string; auth: 'oauth' | 'credentials'; credentialType: string; fields: ProviderField[]
}
export type DeletePreview = {
  previewId: string; providerId: string; bundleId: string; appId: string
  items: number | null; bytes: number | null; dependentBundleCount: number
  dependentBundles: { id: string; name?: string }[]; physicalBytes?: number; packCount?: number
  requiresDependencyAcknowledgement: boolean
}
export type RestoreMode = 'create_new' | 'merge' | 'replace'
export type RestorePlan = {
  providerId: string; bundleId: string; appId: string; destination: string
  fileIds?: string[]; mode: RestoreMode
}
export type RestorePreview = {
  previewId: string; files: number; bytes: number
  conflicts: { path: string; reason?: string }[]
  requiresOverwriteAcknowledgement: boolean
  conflictCount?: number; blockingConflicts?: number; replacementCount?: number; metadataChangeCount?: number
  expiresAt?: string; summary?: string
}
export type PageResult<T> = { items: T[]; nextCursor: string | null }
type Inputs = Record<string, string>
export type ActionParams = {
  migrate_vault: Record<string, never>
  setup_local_tracking: Record<string, never>
  authorize_tracking_storage: Record<string, never>
  connect_provider: {
    kind: string; name: string; bucket?: string; prefix?: string; fields?: Inputs
    credentials?: { type: string; value: Inputs }
  }
  connect_oauth: { kind: string; name: string; clientId?: string; clientSecret?: string; fields?: Inputs }
  disconnect_provider: { providerId: string }
  verify_provider: { providerId: string }
  reauthorize_provider: { providerId: string; credentials?: { type: string; value: Inputs } }
  export_recovery_key: { providerId: string; destination: string }
  authorize_provider_writes: { providerId: string }
  discover_noland_import: Record<string, never>
  import_noland: { sourceId?: string; stateFile?: string; profileIds?: string[] }
  enable_app_tracking: { enabled: boolean; defaultProviderId?: string; roles?: TrackingRole[] }
  refresh_app_tracking: Record<string, never>
  track_software: { appId?: string; name: string; roots: { path: string; role?: string }[]; providerId?: string }
  add_files: { paths: string[]; providerId?: string }
  set_provider: { softwareId: string; providerId: string }
  set_autosave: { softwareId: string; providerId: string; enabled: boolean }
  upload: { softwareId: string; providerId: string; fileIds?: string[] }
  preview_upload_all: UploadBatchPlan
  upload_all: { planSetId: string }
  preview_restore: RestorePlan
  download: { restorePreviewId: string; overwriteAcknowledgement: boolean }
  preview_delete: { providerId: string; bundleId: string; appId: string }
  delete_cloud: { providerId: string; previewId: string; acknowledgeDependencies: boolean }
  cancel: { operationId: string }
  retry: { operationId: string }
  recover_restore: { operationId: string }
}
export type Action = keyof ActionParams

const MAX_TEXT = 4_096
const MAX_INPUT_BYTES = 256 * 1_024
export const FILE_PAGE_SIZE = 100
export const MAX_SELECTION = 512
export const MAX_APP_SELECTION = 512
const MAX_CURSOR = 8_192
export const nativeRuntime = () => isTauri()

// Format metadata only: never credentials, encrypted payloads, or unlock proof.
export type VaultStatus = {
  format: 'legacy' | 'encrypted_state'
  secretsInPlaintext: false
  nativeAuthorizationVerified: false
  legacyInventorySupported?: boolean
  legacyMigrationLimitation?: string
  credentialSetupPending?: boolean
}
export function normalizeVaultStatus(value: unknown): VaultStatus {
  const item = record(value)
  if (!item || !['legacy', 'encrypted_state'].includes(String(item.format))
    || item.secretsInPlaintext !== false || item.nativeAuthorizationVerified !== false) {
    throw new Error('The local vault format could not be verified. Workspace startup remains paused.')
  }
  return {
    format: item.format as VaultStatus['format'],
    secretsInPlaintext: false, nativeAuthorizationVerified: false,
    ...(typeof item.credentialSetupPending === 'boolean' ? { credentialSetupPending: item.credentialSetupPending } : {}),
    ...(typeof item.legacyInventorySupported === 'boolean' ? { legacyInventorySupported: item.legacyInventorySupported } : {}),
    ...(typeof item.legacyMigrationLimitation === 'string'
      ? { legacyMigrationLimitation: item.legacyMigrationLimitation.slice(0, MAX_TEXT) } : {}),
  }
}

export type VaultReadiness = { ready: boolean; issue?: string }
export function normalizeVaultReadiness(value: unknown): VaultReadiness {
  const item = record(value)
  if (!item || typeof item.ready !== 'boolean') {
    throw new Error('Local tracking storage readiness could not be verified. Workspace startup remains paused.')
  }
  // Backend diagnostics are not authority and are never reflected verbatim.
  return {
    ready: item.ready,
    ...(!item.ready ? { issue: 'Local tracking storage is unavailable. Native authorization may be required; damaged storage cannot be reset here.' } : {}),
  }
}

export function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : null
}
export function safeError(value: unknown): string {
  const message = value instanceof Error ? value.message
    : typeof value === 'string' ? value : record(value)?.message
  return typeof message === 'string' ? message.slice(0, MAX_TEXT)
    : 'The native request could not be completed.'
}
function text(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= MAX_TEXT
    && !/[\u0000-\u001f\u007f]/.test(value)
    ? value : undefined
}
function requiredText(value: unknown): string {
  const result = text(value)
  if (!result) throw new Error('The native response contains missing or oversized text.')
  return result
}
function cursorText(value: unknown): string {
  if (typeof value !== 'string' || !value.length || value.length > MAX_CURSOR || /[\u0000-\u0020\u007f]/.test(value)) {
    throw new Error('The native cursor is invalid or exceeds the bounded display limit.')
  }
  return value
}
function count(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined
}
function requiredCount(value: unknown): number {
  const result = count(value)
  if (result === undefined) throw new Error('The native response contains an invalid count.')
  return result
}
function bool(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new Error('The native response contains an invalid setting.')
  return value
}
function member<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) {
    throw new Error('The native response contains an unsupported state.')
  }
  return value as T
}
function list<T>(value: unknown, max: number, parse: (entry: Record<string, unknown>) => T): T[] {
  if (!Array.isArray(value) || value.length > max) {
    throw new Error('The native list is invalid or exceeds the bounded display limit.')
  }
  const seen = new Set<string>()
  return value.map((entry) => {
    const item = record(entry)
    if (!item) throw new Error('The native list contains an invalid item.')
    const parsed = parse(item)
    const id = text(record(parsed)?.id) ?? text(record(parsed)?.kind)
    if (id && seen.has(id)) throw new Error('The native list contains duplicate identifiers.')
    if (id) seen.add(id)
    return parsed
  })
}
function texts(value: unknown, max: number): string[] {
  if (!Array.isArray(value) || value.length > max) {
    throw new Error('The native list is invalid or exceeds the bounded display limit.')
  }
  return value.map(requiredText)
}
function provider(item: Record<string, unknown>): Provider {
  return {
    id: requiredText(item.id), name: requiredText(item.name), kind: requiredText(item.kind),
    status: member(item.status, ['connected', 'connecting', 'disconnected', 'error']),
    origin: item.origin == null ? undefined : member(item.origin, ['quicksave', 'noland'] as const),
    readOnly: item.readOnly == null ? item.origin === 'noland' : bool(item.readOnly), error: text(item.error),
  }
}
function software(item: Record<string, unknown>): Software {
  return {
    id: requiredText(item.id), appId: text(item.appId), name: requiredText(item.name),
    tracked: bool(item.tracked), providerId: text(item.providerId),
    status: member(item.status, ['needs_backup', 'saved', 'checking', 'uploading', 'error', 'not_tracked']),
    autosave: bool(item.autosave), dirty: item.dirty == null ? undefined : bool(item.dirty),
    lastSavedAt: text(item.lastSavedAt), fileCount: count(item.fileCount),
    logicalBytes: count(item.logicalBytes), error: text(item.error),
    roots: item.roots == null ? undefined : list(item.roots, 64, (root) => ({
      id: requiredText(root.id), path: requiredText(root.path), role: text(root.role),
      roles: root.roles == null ? undefined : texts(root.roles, 16),
      fileCount: count(root.fileCount), logicalBytes: count(root.logicalBytes),
    })),
  }
}
export function normalizeActivity(value: unknown): Activity {
  const item = record(value)
  if (!item) throw new Error('The native activity response is invalid.')
  return {
    id: requiredText(item.id), name: requiredText(item.name),
    kind: member(item.kind, ['upload', 'download', 'delete', 'connect', 'autosave']),
    state: member(item.state, ['queued', 'running', 'completed', 'failed', 'cancelled', 'interrupted']),
    providerId: text(item.providerId), softwareId: text(item.softwareId), phase: text(item.phase),
    planSetId: text(item.planSetId),
    completedBytes: count(item.completedBytes), totalBytes: count(item.totalBytes),
    completedFiles: count(item.completedFiles), totalFiles: count(item.totalFiles),
    error: text(item.error), startedAt: text(item.startedAt), finishedAt: text(item.finishedAt),
    canCancel: item.canCancel === true, canRetry: item.canRetry === true, canRecover: item.canRecover === true,
  }
}
export function normalizeDashboard(value: unknown): Dashboard {
  const item = record(value)
  const summary = record(item?.summary)
  if (!item || !summary) throw new Error('The native workspace response is invalid.')
  return {
    providers: list(item.providers, 128, provider),
    software: list(item.software, 10_000, software),
    activity: list(item.activity, 128, normalizeActivity),
    activityUnavailable: item.activityUnavailable == null ? false : bool(item.activityUnavailable),
    activityIssue: text(item.activityIssue),
    summary: {
      needsBackup: requiredCount(summary.needsBackup),
      autosaveEnabled: requiredCount(summary.autosaveEnabled),
      connectedProviders: requiredCount(summary.connectedProviders),
    },
  }
}
export function normalizeAppTracking(value: unknown): AppTracking {
  const item = record(value)
  if (!item) throw new Error('The native app-tracking response is invalid.')
  const completedApps = requiredCount(item.completedApps)
  const totalApps = requiredCount(item.totalApps)
  if (completedApps > totalApps) throw new Error('The native app-tracking counts do not match.')
  return {
    enabled: bool(item.enabled), scanning: bool(item.scanning), completedApps, totalApps,
    diagnostics: item.diagnostics == null ? [] : list(item.diagnostics, 256, (diagnostic) => ({
      appId: text(diagnostic.appId), name: text(diagnostic.name), code: text(diagnostic.code),
      message: requiredText(diagnostic.message), path: text(diagnostic.path),
    })),
  }
}
export function normalizeNoLandDiscovery(value: unknown): NoLandDiscovery {
  const item = record(value)
  if (!item) throw new Error('The native No Land discovery response is invalid.')
  const candidates = list(item.candidates, 64, (source) => ({
    id: requiredText(source.id), label: requiredText(source.label), path: requiredText(source.path),
    modifiedAt: text(source.modifiedAt), profileCount: count(source.profileCount),
  }))
  const selectedId = item.selectedId == null ? undefined : requiredText(item.selectedId)
  if (selectedId && !candidates.some((source) => source.id === selectedId)) {
    throw new Error('The selected No Land source is not in the native discovery result.')
  }
  return { candidates, selectedId }
}
export function normalizeProviderTypes(value: unknown): ProviderType[] {
  // The native workspace returns the audited No Land provider definition array.
  return list(value, 128, (item) => {
    const fieldNames = new Set<string>()
    const fields = list(item.fields, 40, (field): ProviderField => {
      const name = requiredText(field.key)
      if (fieldNames.has(name)) throw new Error('The native provider schema has duplicate fields.')
      fieldNames.add(name)
      const type = member(field.fieldType, ['text', 'password', 'select', 'number', 'toggle'] as const)
      const credential = bool(field.credential)
      return {
        name, label: requiredText(field.label), required: bool(field.required), credential,
        secret: credential || type === 'password', type,
        options: field.options == null ? undefined : list(field.options, 100, (option) => ({
          value: requiredText(option.value), label: requiredText(option.label),
        })),
      }
    })
    return {
      kind: requiredText(item.kind), name: requiredText(item.label),
      auth: bool(item.isOauth) ? 'oauth' : 'credentials',
      credentialType: requiredText(item.credentialType), fields,
    }
  })
}
export function normalizeFiles(value: unknown): PageResult<FileItem> {
  const item = record(value)
  return {
    items: list(item?.files, FILE_PAGE_SIZE, (file) => ({
      id: requiredText(file.id), name: requiredText(file.name), path: requiredText(file.path),
      directory: bool(file.directory), size: requiredCount(file.size),
      status: text(file.status), rootId: text(file.rootId), role: text(file.role),
    })),
    nextCursor: item?.nextCursor == null ? null : cursorText(item.nextCursor),
  }
}
function optionalBool(value: unknown): boolean | undefined {
  return value == null ? undefined : bool(value)
}
function bundle(item: Record<string, unknown>): Bundle {
  const completeness = item.completeness == null ? undefined : member(item.completeness,
    ['unknown', 'selected_files', 'approved_software', 'personal_state', 'complete_application'] as const)
  const mode = item.mode == null ? undefined : member(item.mode, ['complete_application', 'personal_state', 'custom'] as const)
  const completeApplication = optionalBool(item.completeApplication)
  const sourceReadiness = item.readiness == null ? null : record(item.readiness)
  if (item.readiness != null && !sourceReadiness) throw new Error('The native backup readiness is invalid.')
  const readiness = sourceReadiness ? {
    metadataVerified: bool(sourceReadiness.metadataVerified), filesAvailable: bool(sourceReadiness.filesAvailable),
    applicationReady: bool(sourceReadiness.applicationReady),
    requiresNativeRestorePreview: bool(sourceReadiness.requiresNativeRestorePreview),
  } : undefined
  if ((completeApplication === true && (completeness !== 'complete_application' || mode !== 'complete_application' || !count(item.fileCount)))
    || (readiness?.applicationReady && (completeApplication !== true || !count(item.fileCount)))) {
    throw new Error('Partial or unknown backup coverage cannot be represented as a complete application.')
  }
  return {
    id: requiredText(item.id), appId: requiredText(item.appId), name: requiredText(item.name),
    providerId: requiredText(item.providerId), createdAt: text(item.createdAt),
    fileCount: count(item.fileCount), logicalBytes: count(item.logicalBytes),
    platform: text(item.platform), format: text(item.format), compatibility: text(item.compatibility),
    sourceBundleId: text(item.sourceBundleId), sourceAppId: text(item.sourceAppId),
    commitId: text(item.commitId), parentBundleId: item.parentBundleId === null ? null : text(item.parentBundleId),
    sourceInstanceId: text(item.sourceInstanceId), mode, completeness, captureScopeLabel: text(item.captureScopeLabel),
    storedIncrementalBytes: count(item.storedIncrementalBytes), tombstoneCount: count(item.tombstoneCount),
    completeApplication, subset: item.subset === null ? null : optionalBool(item.subset),
    readiness, currentHead: optionalBool(item.currentHead), currentCompleteHead: optionalBool(item.currentCompleteHead),
    currentPersonalStateHead: optionalBool(item.currentPersonalStateHead),
  }
}
function catalogMeta(item: Record<string, unknown> | null, providerId?: string) {
  if (!item || (providerId && item.providerId != null && item.providerId !== providerId)) {
    throw new Error('The native catalog provider does not match this connection.')
  }
  if (item.authoritativeForExecution != null && item.authoritativeForExecution !== false) {
    throw new Error('Catalog metadata cannot authorize an upload, restore or deletion.')
  }
  const freshness = item.freshness == null ? null : record(item.freshness)
  if (item.freshness != null && !freshness) throw new Error('The native catalog freshness is invalid.')
  return {
    providerId: text(item.providerId), revision: text(item.revision), catalogCommitId: text(item.catalogCommitId),
    freshness: freshness ? {
      source: text(freshness.source), refreshStartedAt: text(freshness.refreshStartedAt),
      observedAt: text(freshness.observedAt), coalesced: bool(freshness.coalesced),
    } : undefined,
    authoritativeForExecution: item.authoritativeForExecution === false ? false as const : undefined,
    nextCursor: item.nextCursor == null ? null : cursorText(item.nextCursor),
  }
}
export function normalizeBundles(value: unknown, providerId?: string, appId?: string): CatalogPage<Bundle> {
  const item = record(value)
  const items = list(item?.bundles, 100, bundle)
  if (items.some((entry) => (providerId && entry.providerId !== providerId) || (appId && entry.appId !== appId))) {
    throw new Error('The native backup history belongs to a different provider or application.')
  }
  return {
    ...catalogMeta(item, providerId), items,
  }
}
export function normalizePendingDeletions(value: unknown, providerId?: string): CatalogPage<PendingDeletion> {
  const item = record(value)
  const plans = new Set<string>()
  const items = list(item?.pendingDeletions, 100, (plan): PendingDeletion => {
    const planId = requiredText(plan.planId)
    if (plans.has(planId)) throw new Error('The native list contains duplicate pending deletion identifiers.')
    plans.add(planId)
    const dependenciesKnown = bool(plan.dependenciesKnown)
    const dependentCount = count(plan.dependentCount)
    if (dependenciesKnown && dependentCount === undefined) throw new Error('The native deletion dependency count is missing.')
    return {
      planId, operationId: text(plan.operationId), digest: text(plan.digest),
      names: texts(plan.names, 16), nameCount: count(plan.nameCount),
      detailsAvailable: bool(plan.detailsAvailable), requiresNativePlanLoad: bool(plan.requiresNativePlanLoad),
      dependenciesKnown, requestedCount: count(plan.requestedCount), affectedCount: count(plan.affectedCount),
      dependentCount, logicalBytes: count(plan.logicalBytes), physicalBytes: count(plan.physicalBytes),
      packCount: count(plan.packCount), metadataObjectCount: count(plan.metadataObjectCount),
    }
  })
  return { ...catalogMeta(item, providerId), items }
}
export function normalizeUploadBatchPreview(value: unknown, expected: UploadBatchPlan): UploadBatchPreview {
  const item = record(value)
  if (!item || item.providerId !== expected.providerId) throw new Error('The native batch belongs to a different provider.')
  const softwareCount = requiredCount(item.softwareCount)
  if (softwareCount < 1 || softwareCount > 4_096
    || (expected.softwareIds && softwareCount !== expected.softwareIds.length)) {
    throw new Error('The native frozen app selection does not match this batch.')
  }
  const detail = record(item.summary) ?? item
  if (detail.keepsLocalData !== undefined && detail.keepsLocalData !== true) {
    throw new Error('A batch upload must keep local data.')
  }
  return {
    planSetId: requiredText(item.planSetId), providerId: expected.providerId, softwareCount,
    summary: text(item.summary), sampleNames: detail.sampleNames == null ? undefined : texts(detail.sampleNames, 16),
    createdAt: text(detail.createdAt), jobCount: count(detail.jobCount),
    fileCount: count(detail.fileCount), logicalBytes: count(detail.logicalBytes),
    selection: detail.selection == null ? undefined : member(detail.selection, ['all_approved_apps', 'selected_apps'] as const),
    fileCapture: text(detail.fileCapture), selectionFrozen: text(detail.selectionFrozen),
  }
}
export function normalizeBatchStatus(value: unknown, operationId: string, planSetId?: string): BatchStatus {
  const item = record(value)
  if (!item || item.operationId !== operationId) throw new Error('The native batch operation identifier does not match.')
  if ((item.id !== undefined && item.id !== operationId)
    || (planSetId && item.planSetId !== undefined && item.planSetId !== planSetId)) {
    throw new Error('The native batch belongs to a different frozen operation or plan set.')
  }
  // The actual gateway returns Activity + `batch`, initially null. The native
  // coordinator's bare OperationSummary is also readable, without inventing totals.
  const detail = item.batch === undefined ? item : item.batch === null ? null : record(item.batch)
  if (item.batch != null && !detail) throw new Error('The native batch summary is invalid.')
  const counts = detail ? {
    completed: requiredCount(detail.completed), failed: requiredCount(detail.failed),
    cancelled: requiredCount(detail.cancelled), interrupted: requiredCount(detail.interrupted),
    active: requiredCount(detail.active), notStarted: requiredCount(detail.notStarted),
    unknown: requiredCount(detail.unknown), awaitingFinalization: requiredCount(detail.awaitingFinalization),
  } : {}
  const childCount = detail ? requiredCount(detail.softwareCount ?? detail.childCount) : undefined
  const jobCount = detail ? requiredCount(detail.jobCount) : undefined
  if (childCount !== undefined && jobCount !== undefined
    && (childCount < 1 || childCount > 4_096 || jobCount < 1 || jobCount > 32)) {
    throw new Error('The native batch exceeds its bounded app/job limit.')
  }
  if (childCount !== undefined && Object.values(counts).some((value) => value! > childCount)) {
    throw new Error('The native batch counts do not match its frozen selection.')
  }
  const state = member(item.state, ['queued', 'running', 'finalizing', 'completed', 'failed', 'cancelled', 'interrupted', 'unknown'])
  return {
    operationId, childCount, jobCount, ...counts,
    state: state === 'running' && item.phase === 'native_status_unavailable' ? 'unknown'
      : state === 'running' && item.phase === 'finalizing' ? 'finalizing' : state,
    cancelRequested: optionalBool(item.cancelRequested), canCancel: item.canCancel === true,
    canRetry: bool(item.canRetry), shutdownBlocked: detail ? bool(detail.closeBlocked ?? detail.shutdownBlocked) : undefined,
    progress: detail ? list(detail.progress, 64, (progress) => ({
      phase: requiredText(progress.phase), unit: requiredText(progress.unit),
      completed: requiredCount(progress.completed), total: count(progress.total),
      reportingChildren: requiredCount(progress.reportingChildren),
    })) : [],
  }
}
export function normalizeDeletePreview(value: unknown, expected?: { providerId: string; bundleId: string; appId: string }): DeletePreview {
  const item = record(value)
  if (!item) throw new Error('The native deletion preview is invalid. Request a new preview.')
  const providerId = requiredText(item.providerId)
  const bundleId = requiredText(item.bundleId)
  const appId = requiredText(item.appId)
  if (expected && (expected.providerId !== providerId || expected.bundleId !== bundleId || expected.appId !== appId)) {
    throw new Error('The deletion preview belongs to a different backup scope.')
  }
  const dependentBundleCount = requiredCount(item.dependentBundleCount)
  const dependentBundles = list(item.dependentBundles, 256, (dependency) => ({
    id: requiredText(dependency.id), name: text(dependency.name),
  }))
  if (dependentBundles.length > dependentBundleCount) throw new Error('The native deletion dependency counts do not match.')
  return {
    previewId: requiredText(item.previewId), providerId, bundleId, appId,
    items: count(item.items) ?? count(item.fileCount) ?? null, bytes: count(item.logicalBytes) ?? null,
    dependentBundles, dependentBundleCount,
    physicalBytes: count(item.physicalBytes), packCount: count(item.packCount),
    requiresDependencyAcknowledgement: dependentBundleCount > 0,
  }
}
export function normalizeRestorePreview(value: unknown, expected?: RestorePlan): RestorePreview {
  const item = record(value)
  if (!item) throw new Error('The native restore preview is invalid. Request a new preview.')
  // Some runtimes echo the scope for inspection; never accept a mismatched echo.
  // The opaque preview ID, not JS paths, authorizes the final native operation.
  if (expected) {
    for (const key of ['providerId', 'bundleId', 'appId', 'destination', 'mode'] as const) {
      if (item[key] !== undefined && item[key] !== expected[key]) {
        throw new Error('The restore preview belongs to a different restore plan.')
      }
    }
    if (item.fileIds !== undefined && JSON.stringify(item.fileIds) !== JSON.stringify(expected.fileIds)) {
      throw new Error('The restore preview belongs to a different file selection.')
    }
  }
  const conflicts = list(item.conflicts, 256, (conflict) => ({
    path: requiredText(conflict.path), reason: text(conflict.reason),
  }))
  const conflictCount = item.conflictCount == null ? undefined : requiredCount(item.conflictCount)
  const blockingConflicts = item.blockingConflicts == null ? undefined : requiredCount(item.blockingConflicts)
  if (conflictCount !== undefined && (conflicts.length > conflictCount || (blockingConflicts ?? 0) > conflictCount)) {
    throw new Error('The native restore conflict sample does not match its total inventory.')
  }
  return {
    previewId: requiredText(item.previewId), files: requiredCount(item.files), bytes: requiredCount(item.bytes),
    conflicts,
    requiresOverwriteAcknowledgement: bool(item.requiresOverwriteAcknowledgement),
    conflictCount, blockingConflicts,
    replacementCount: item.replacementCount == null ? undefined : requiredCount(item.replacementCount),
    metadataChangeCount: item.metadataChangeCount == null ? undefined : requiredCount(item.metadataChangeCount),
    expiresAt: text(item.expiresAt), summary: text(item.summary),
  }
}
export function terminal(state: Activity['state']): boolean {
  return state !== 'queued' && state !== 'running'
}

async function command(name: string, args: Record<string, unknown>): Promise<unknown> {
  if (!nativeRuntime()) throw new Error('Open QuickSave desktop to use native actions.')
  return invoke(name, args)
}
function captureParams(params: object): Record<string, unknown> {
  const encoded = JSON.stringify(params)
  if (new TextEncoder().encode(encoded).byteLength > MAX_INPUT_BYTES) {
    throw new Error('This selection exceeds the native request size limit. Choose fewer files.')
  }
  return JSON.parse(encoded) as Record<string, unknown>
}
async function query(name: string, params: object = {}): Promise<unknown> {
  return command('workspace_query', { query: name, params: captureParams(params) })
}
async function action<A extends Action>(name: A, params: ActionParams[A], signal?: AbortSignal): Promise<unknown> {
  // Clone the exact plan before awaiting consent. Execute receives only a one-use
  // ticket, never a replacement path, credential, subset, or dependency checkbox.
  const captured = captureParams(params)
  if (['migrate_vault', 'setup_local_tracking', 'authorize_tracking_storage'].includes(name) && Object.keys(captured).length !== 0) {
    throw new Error('Local vault actions accept no caller-supplied parameters.')
  }
  if ('fileIds' in captured && (!Array.isArray(captured.fileIds)
    || captured.fileIds.length === 0 || captured.fileIds.length > MAX_SELECTION
    || !captured.fileIds.every((id) => text(id)) || new Set(captured.fileIds).size !== captured.fileIds.length)) {
    throw new Error('Choose between 1 and 512 individual files.')
  }
  if ('softwareIds' in captured && (!Array.isArray(captured.softwareIds)
    || captured.softwareIds.length === 0 || captured.softwareIds.length > MAX_APP_SELECTION
    || !captured.softwareIds.every((id) => text(id) && !['_all', '.', '..'].includes(id) && !/[\\/*?[\]]/.test(id))
    || new Set(captured.softwareIds).size !== captured.softwareIds.length)) {
    throw new Error('Choose between 1 and 512 exact app identities, or use the native all-apps preview.')
  }
  if (name === 'upload_all') {
    const id = requiredText(captured.planSetId)
    if (['*', '_all'].includes(id)) throw new Error('Batch upload requires a frozen native plan-set ID, not a wildcard.')
    if (Object.keys(captured).some((key) => key !== 'planSetId')) {
      throw new Error('Batch upload requires only a frozen native plan-set ID.')
    }
  }
  if (name === 'download') {
    requiredText(captured.restorePreviewId)
    bool(captured.overwriteAcknowledgement)
    if (Object.keys(captured).some((key) => !['restorePreviewId', 'overwriteAcknowledgement'].includes(key))) {
      throw new Error('Download requires a frozen native restore preview, not a replacement restore plan.')
    }
  }
  if (name === 'reauthorize_provider'
    && Object.keys(captured).some((key) => !['providerId', 'credentials'].includes(key))) {
    throw new Error('Reauthorization cannot change a provider kind, client, root or routing fields.')
  }
  if (name === 'export_recovery_key'
    && Object.keys(captured).some((key) => !['providerId', 'destination'].includes(key))) {
    throw new Error('Recovery export accepts only the provider and exact new external destination.')
  }
  try {
    if (signal?.aborted) throw new Error('The request was cancelled before native execution.')
    const prepared = record(await command('workspace_prepare', { action: name, params: captured }))
    const ticketId = requiredText(prepared?.ticketId)
    if (new TextEncoder().encode(ticketId).byteLength > MAX_TEXT) {
      throw new Error('The native confirmation did not return a valid ticket.')
    }
    if (signal?.aborted) throw new Error('The request was cancelled before native execution.')
    return await command('workspace_execute', { ticketId })
  } catch (error) {
    // A backend error must never reflect transient credentials back into the UI.
    if (name === 'reauthorize_provider') {
      throw new Error('Reauthorization was cancelled or failed. Check native provider status; it has not been marked verified by this request.')
    }
    if (name === 'connect_provider' || name === 'connect_oauth') {
      if (name === 'connect_oauth' && /native oauth.*not available/i.test(safeError(error))) {
        throw new Error('Native OAuth is not available in this runtime. No account was connected.')
      }
      throw new Error('Connection was cancelled or could not be completed. Review the provider settings and try again.')
    }
    throw error
  } finally {
    // Drop references as soon as the IPC pair settles; never persist/cache inputs.
    for (const key of Object.keys(captured)) delete captured[key]
  }
}
export const api = {
  vaultStatus: async () => normalizeVaultStatus(await query('vault_status')),
  vaultReadiness: async () => normalizeVaultReadiness(await query('vault_readiness')),
  dashboard: async () => normalizeDashboard(await query('dashboard')),
  providerTypes: async () => normalizeProviderTypes(await query('provider_types')),
  software: async () => list(record(await query('software'))?.software, 10_000, software),
  appTracking: async () => normalizeAppTracking(await query('app_tracking')),
  softwareFiles: async (softwareId: string, cursor?: string) =>
    normalizeFiles(await query('software_files', { softwareId, cursor, limit: FILE_PAGE_SIZE })),
  bundles: async (providerId: string, cursor?: string) =>
    normalizeBundles(await query('bundles', { providerId, cursor, limit: FILE_PAGE_SIZE }), providerId),
  history: async (providerId: string, appId: string, cursor?: string) =>
    normalizeBundles(await query('history', { providerId, appId, cursor, limit: FILE_PAGE_SIZE }), providerId, appId),
  pendingDeletions: async (providerId: string, cursor?: string) =>
    normalizePendingDeletions(await query('pending_deletions', { providerId, cursor, limit: FILE_PAGE_SIZE }), providerId),
  batchStatus: async (planSetId: string, operationId = planSetId) =>
    normalizeBatchStatus(await query('batch_status', { planSetId }), operationId, planSetId),
  bundleFiles: async (providerId: string, bundleId: string, appId: string, cursor?: string) =>
    normalizeFiles(await query('bundle_files', { providerId, bundleId, appId, cursor, limit: FILE_PAGE_SIZE })),
  activity: async () => list(record(await query('activity'))?.activity, 128, normalizeActivity),
  operation: async (operationId: string) => {
    const result = normalizeActivity(await query('operation', { operationId }))
    if (result.id !== operationId) throw new Error('The native operation identifier does not match.')
    return result
  },
  action,
}

export async function chooseFolder(title: string): Promise<string | null> {
  if (!nativeRuntime()) throw new Error('Open QuickSave desktop to choose a folder.')
  const selected = await open({ title, directory: true, multiple: false })
  if (selected === null) return null
  return requiredText(selected)
}
export async function chooseFiles(): Promise<string[] | null> {
  if (!nativeRuntime()) throw new Error('Open QuickSave desktop to choose files.')
  const selected = await open({ title: 'Add files to QuickSave', directory: false, multiple: true })
  if (selected === null) return null
  const paths = typeof selected === 'string' ? [selected] : selected
  if (paths.length === 0 || paths.length > MAX_SELECTION) {
    throw new Error('Choose between 1 and 512 files at a time.')
  }
  return paths.map(requiredText)
}

export async function chooseNoLandState(): Promise<string | null> {
  if (!nativeRuntime()) throw new Error('Open QuickSave desktop to import No Land.')
  const selected = await open({
    title: 'Choose No Land state.json', directory: false, multiple: false,
    filters: [{ name: 'JSON state', extensions: ['json'] }],
  })
  if (selected === null) return null
  const path = requiredText(selected)
  if (!path.startsWith('/') && !/^[A-Za-z]:[\\/]/.test(path)) {
    throw new Error('The native picker did not return an absolute state-file path.')
  }
  return path
}

export async function chooseRecoveryDestination(): Promise<string | null> {
  if (!nativeRuntime()) throw new Error('Open QuickSave desktop to export a recovery key.')
  const selected = await save({
    title: 'Export recovery key to a new external private file',
    defaultPath: 'QuickSave-recovery.key',
    filters: [{ name: 'Recovery key', extensions: ['key'] }],
  })
  if (selected === null) return null
  const path = requiredText(selected)
  if (!path.startsWith('/') && !/^[A-Za-z]:[\\/]/.test(path)) {
    throw new Error('The native save picker did not return an absolute destination.')
  }
  return path
}
