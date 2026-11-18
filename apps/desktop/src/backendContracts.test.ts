import { describe, expect, it } from 'vitest'
import { normalizeBatchStatus, normalizeBundles, normalizePendingDeletions } from './api'
import { backupScope } from './CatalogDetails'
import { backendSource, catalogBackendFixture, pendingBackendFixture } from './test/backendFixtures'
import { batchPreview, batchResponse, batchStatus } from './test/fixtures'

describe('actual backend fixture and projection compatibility (source-only, no native execution)', () => {
  it('consumes the Rust catalog fixture without dropping original identity, lineage, modes or readiness', () => {
    const native = catalogBackendFixture()
    const page = normalizeBundles(native, 'fixture-provider')
    expect(page.items).toHaveLength(3)
    expect(page.items[2]).toMatchObject({
      id: '00000000-0000-0000-0000-000000000003',
      appId: 'desktop:original', mode: 'custom', completeness: 'selected_files',
      commitId: '00000000-0000-0000-0000-000000000067',
      parentBundleId: '00000000-0000-0000-0000-000000000002',
      sourceInstanceId: '00000000-0000-0000-0000-0000000001f5',
      currentHead: true, completeApplication: false,
      readiness: { metadataVerified: true, filesAvailable: true, applicationReady: false, requiresNativeRestorePreview: true },
    })
    expect(page.freshness?.observedAt).toBe('2026-11-17T00:00:04Z')
    expect(page.authoritativeForExecution).toBe(false)
    expect(page.items[0].currentCompleteHead).toBe(true)
    expect(backupScope(page.items[0])).toBe('Selected files only')
  })
  it('reads the actual pending plan fixture and applies its source summary projection without guessing dependency membership', () => {
    const native = pendingBackendFixture()
    const page = normalizePendingDeletions({ pendingDeletions: [native] })
    expect(page.items[0]).toMatchObject({
      planId: '00000000-0000-0000-0000-000000000384',
      operationId: '00000000-0000-0000-0000-000000000384',
      requestedCount: 1, affectedCount: 2, dependentCount: 1, dependenciesKnown: true,
      logicalBytes: 40, physicalBytes: 30, requiresNativePlanLoad: true,
    })
    expect(page.items[0]).not.toHaveProperty('targets')
    expect(page.items[0]).not.toHaveProperty('requested')
  })
  it('guards the frontend field names against the actual native catalog projection rather than a fake complete-app mode', () => {
    const source = backendSource('crates/quicksave-noland/src/catalog_control.rs')
    for (const field of ['sourceInstanceId', 'parentBundleId', 'commitId', 'captureScopeLabel', 'completeness',
      'currentCompleteHead', 'currentPersonalStateHead', 'requiresNativeRestorePreview']) expect(source).toContain(`"${field}"`)
    expect(source).toContain('"fileCount":detail.map(|detail|detail.file_count)')
    expect(source).toContain('Coverage::Unknown')
    const fixture = catalogBackendFixture()
    const bundles = fixture.bundles as Record<string, unknown>[]
    expect(() => normalizeBundles({ bundles: [{
      ...bundles[0], completeApplication: true,
    }] })).toThrow('Partial or unknown')
  })
  it('checks native restore projection keeps count aliases and a bounded conflict sample as distinct fields', () => {
    const source = backendSource('crates/quicksave-service/src/workspace_restore.rs')
    for (const field of ['files', 'bytes', 'conflictCount', 'conflicts', 'blockingConflicts',
      'requiresOverwriteAcknowledgement']) expect(source).toContain(`"${field}"`)
    expect(source).toContain('summary["files"] = json!(count)')
    expect(source).toContain('summary["conflicts"] = json!(conflicts)')
  })
  it('checks batch_status against the actual group Activity projection with nullable totals, not a made-up flat job response', () => {
    const source = backendSource('crates/quicksave-service/src/batch.rs')
    const projection = source.slice(source.indexOf('fn group_activity('))
    for (const field of ['operationId', 'planSetId', 'canCancel', 'canRetry', 'batch', 'softwareCount', 'jobCount',
      'notStarted', 'awaitingFinalization', 'progress', 'closeBlocked']) expect(projection).toContain(`"${field}"`)
    expect(projection).toContain('"batch":summary.map(')
    const parsed = normalizeBatchStatus(batchResponse(), batchStatus.operationId, batchPreview.planSetId)
    expect(parsed.childCount).toBe(1)
    expect(parsed.shutdownBlocked).toBe(true)
    expect(parsed.progress[0].total).toBeUndefined()
    const preparing = normalizeBatchStatus({ ...batchResponse(), state: 'queued', batch: null }, batchStatus.operationId)
    expect(preparing.childCount).toBeUndefined()
    expect(preparing.completed).toBeUndefined()
  })
})
