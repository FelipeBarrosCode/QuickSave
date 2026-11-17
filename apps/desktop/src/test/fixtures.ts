// Test-only in-memory responses. Never imported by the application.
export const capabilities = {
  product: 'QuickSave',
  localFolderBackups: true,
  cloudBackups: false,
  platform: {
    platform: 'macos',
    filesystem: {
      native_directory_handles: true,
      handle_anchored_reads: true,
      durable_create_new: true,
      durable_directory_creation: true,
      private_directory_creation: true,
    },
  },
}

export const snapshot = {
  snapshotId: 'test-snapshot-001',
  createdAt: '2026-11-17T10:30:00Z',
  totalFiles: 3,
  logicalBytes: 4096,
}

export const operation = {
  id: 'test-job-001',
  kind: 'backup',
  state: 'running',
  startedAt: '2026-11-17T10:30:00Z',
  finishedAt: null,
  result: null,
  error: null,
}

export const paths = {
  repository: '/isolated-test/repository',
  keyFile: '/isolated-test/external-recovery.key',
  source: '/isolated-test/source',
  destination: '/isolated-test/destination',
}
