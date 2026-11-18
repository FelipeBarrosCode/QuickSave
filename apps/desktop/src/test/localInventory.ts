// SPDX-License-Identifier: GPL-3.0-only
// Test-only native gateway fixture. Never imported by application code.
import { lstatSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { FileItem, Software, SoftwareRoot, TrackingRole } from '../api'

export function createLocalInventoryFixture() {
  const temporary = join(realpathSync(tmpdir()), 'opencode')
  mkdirSync(temporary, { recursive: true })
  const directory = mkdtempSync(join(temporary, 'quicksave-ui-inventory-'))
  const roots: SoftwareRoot[] = []
  const files: FileItem[] = []
  const sources: [TrackingRole, string, string][] = [
    ['installation', 'installed.bin', 'isolated installation fixture'],
    ['save', 'slot.sav', 'isolated saved game fixture'],
    ['config', 'prefs.json', '{"isolated":true}'],
    ['runtime', 'runtime.dat', 'isolated runtime fixture'],
  ]
  try {
    for (const [role, name, content] of sources) {
      const path = join(directory, role)
      mkdirSync(path)
      writeFileSync(join(path, name), content)
      const id = `fixture-root-${role}`
      const entries = readdirSync(path)
      if (entries.length > 32) throw new Error('Test fixture exceeds its bounded native response.')
      let logicalBytes = 0
      for (const entry of entries) {
        const metadata = lstatSync(join(path, entry))
        if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error('Only isolated regular fixture files are allowed.')
        logicalBytes += metadata.size
        files.push({ id: `${id}:${entry}`, name: entry, path: entry, directory: false, size: metadata.size, rootId: id, role })
      }
      roots.push({ id, path, role, fileCount: entries.length, logicalBytes })
    }
    const software: Software = {
      id: 'indexed-fixture-software', appId: 'indexed-fixture-app', name: 'Indexed fixture app',
      tracked: true, status: 'needs_backup', dirty: true, autosave: false, roots,
      fileCount: files.length, logicalBytes: files.reduce((total, file) => total + file.size, 0),
    }
    return { software, files, dispose: () => rmSync(directory, { recursive: true, force: true }) }
  } catch (error) {
    rmSync(directory, { recursive: true, force: true })
    throw error
  }
}
