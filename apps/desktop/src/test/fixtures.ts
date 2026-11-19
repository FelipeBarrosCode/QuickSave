// Synthetic in-memory native responses only. Never imported by application code.
import type { Activity, AppTracking, BatchStatus, Bundle, Dashboard, FileItem, Provider, Software, UploadBatchPreview } from '../api'

export const provider: Provider = {
  id: 'provider-test', name: 'Test drive', kind: 'drive', status: 'connected', readOnly: false, origin: 'quicksave',
}
export const software: Software = {
  id: 'software-test', appId: 'app-test', name: 'Test software', tracked: true,
  providerId: provider.id, status: 'needs_backup', autosave: false, dirty: true, fileCount: 2,
  logicalBytes: 5120,
  roots: [{ id: 'root-test', path: '/isolated-test/software-data', role: 'config' }],
}
export const bundle: Bundle = {
  id: 'bundle-test', appId: software.appId!, providerId: provider.id, name: 'Test backup',
  createdAt: '2026-11-17T10:30:00Z', fileCount: 2, logicalBytes: 4096,
}
export const files: FileItem[] = [
  { id: 'root-test:settings.json', path: 'settings.json', name: 'settings.json', directory: false, size: 4096, rootId: 'root-test', role: 'config' },
  { id: 'root-test:save.dat', path: 'save.dat', name: 'save.dat', directory: false, size: 1024, rootId: 'root-test', role: 'save' },
]
export const activity: Activity = {
  id: 'operation-test', kind: 'upload', name: 'Test upload', state: 'running',
  softwareId: software.id, providerId: provider.id, completedBytes: 1024, totalBytes: 4096,
  completedFiles: 0, totalFiles: 2, canCancel: true,
}
export const dashboard: Dashboard = {
  providers: [provider], software: [software], activity: [],
  summary: { needsBackup: 1, autosaveEnabled: 0, connectedProviders: 1 },
}
export const providerTypes = [
  { kind: 'drive', label: 'Google Drive', isOauth: true, credentialType: 'o_auth2', fields: [
    { key: 'client_id', label: 'Client ID', required: false, credential: false, fieldType: 'text' },
    { key: 'client_secret', label: 'Client secret', required: false, credential: false, fieldType: 'password' },
  ] },
  { kind: 'onedrive', label: 'OneDrive', isOauth: true, credentialType: 'o_auth2', fields: [] },
  { kind: 's3', label: 'S3', isOauth: false, credentialType: 's3', fields: [
    { key: 'bucket', label: 'Bucket', required: true, credential: false, fieldType: 'text' },
    { key: 'access_key_id', label: 'Access key', required: true, credential: true, fieldType: 'text' },
    { key: 'secret_access_key', label: 'Secret key', required: true, credential: true, fieldType: 'password' },
    { key: 'prefix', label: 'Folder / prefix', required: false, credential: false, fieldType: 'text' },
    { key: 'region', label: 'Region', required: true, credential: false, fieldType: 'select', options: [
      { value: 'isolated-test', label: 'Isolated test region' },
    ] },
  ] },
]
export const preview = {
  previewId: 'preview-test', providerId: provider.id, bundleId: bundle.id, appId: bundle.appId,
  items: 2, logicalBytes: 5120, dependentBundleCount: 1,
  dependentBundles: [{ id: 'dependent-test', name: 'Dependent test backup' }],
  physicalBytes: 4096, packCount: 1,
}
export const appTracking: AppTracking = {
  enabled: true, scanning: false, completedApps: 1, totalApps: 1, diagnostics: [],
}
export const importDiscovery = {
  candidates: [{ id: 'noland-source-test', label: 'Test No Land source', path: '/isolated-test/noland/state.json', profileCount: 1 }],
}
export const restorePreview = {
  previewId: 'restore-preview-test', files: 2, bytes: 5120,
  conflicts: [], requiresOverwriteAcknowledgement: false,
}
export const batchPreview: UploadBatchPreview = {
  planSetId: 'batch-plan-test', providerId: provider.id, softwareCount: 1,
  summary: 'Save the exact approved software instances; local files and cloud history are kept.',
  sampleNames: [software.name], jobCount: 1, selection: 'all_approved_apps',
  fileCapture: 'at_each_child_first_execution',
  selectionFrozen: 'software_instances_source_identities_and_exact_approved_roots',
}
export const batchStatus: BatchStatus = {
  operationId: 'batch-operation-test', state: 'running', jobCount: 1, childCount: 1,
  completed: 0, failed: 0, cancelled: 0, interrupted: 0, active: 1, notStarted: 0,
  unknown: 0, awaitingFinalization: 0, cancelRequested: false, canRetry: false,
  canCancel: true, shutdownBlocked: true,
  progress: [{ phase: 'capture', unit: 'bytes', completed: 1024, reportingChildren: 1 }],
}
export function batchResponse(status: BatchStatus = batchStatus) {
  return {
    id: status.operationId, operationId: status.operationId, planSetId: batchPreview.planSetId,
    kind: 'upload', name: 'Save approved software group', providerId: provider.id,
    state: status.state === 'finalizing' || status.state === 'unknown' ? 'running' : status.state,
    phase: status.state === 'finalizing' ? 'finalizing' : status.state === 'unknown' ? 'native_status_unavailable' : 'native_operation',
    canCancel: status.canCancel, canRetry: status.canRetry,
    batch: {
      softwareCount: status.childCount, jobCount: status.jobCount,
      completed: status.completed, failed: status.failed, cancelled: status.cancelled,
      interrupted: status.interrupted, active: status.active, notStarted: status.notStarted,
      unknown: status.unknown, awaitingFinalization: status.awaitingFinalization,
      progress: status.progress, closeBlocked: status.shutdownBlocked,
    },
  }
}
export type Call = { command: string; args: Record<string, unknown> }
export function respond(command: string, args?: Record<string, unknown>): unknown {
  if (command === 'workspace_prepare') return { ticketId: 'test-ticket' }
  if (command === 'workspace_execute') return dashboard
  if (command !== 'workspace_query') throw new Error(`Unexpected test-only command: ${command}`)
  switch (args?.query) {
    case 'vault_status': return { format: 'encrypted_state', secretsInPlaintext: false, nativeAuthorizationVerified: false }
    case 'vault_readiness': return { ready: true }
    case 'dashboard': return dashboard
    case 'provider_types': return providerTypes
    case 'software': return { software: [software] }
    case 'app_tracking': return appTracking
    case 'software_files':
    case 'bundle_files': return { files }
    case 'bundles': return { bundles: [bundle] }
    case 'history': return { bundles: [bundle] }
    case 'pending_deletions': return { pendingDeletions: [] }
    case 'batch_status': return batchResponse()
    case 'activity': return { activity: [] }
    case 'operation': return activity
    default: throw new Error(`Unexpected test-only query: ${args?.query as string}`)
  }
}
export const paths = {
  root: '/isolated-test/software-data',
  file: '/isolated-test/one-file.dat',
  stateFile: '/isolated-test/noland/state.json',
  destination: '/isolated-test/empty-download',
}
