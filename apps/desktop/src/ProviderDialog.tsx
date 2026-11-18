// SPDX-License-Identifier: GPL-3.0-only
import { useEffect, useRef, useState, type FormEvent } from 'react'
import { api, chooseNoLandState, chooseRecoveryDestination, normalizeNoLandDiscovery, record, safeError, type NoLandSource, type Provider, type ProviderType } from './api'
import { date, number } from './format'
import type { QuickSave } from './useQuickSave'
import { Button, Dialog, InlineError } from './ui'
import { ReauthorizeDialog } from './ReauthorizeDialog'

export function ProviderDialog({ model, onClose }: { model: QuickSave; onClose: () => void }) {
  const [types, setTypes] = useState<ProviderType[]>([])
  const [kind, setKind] = useState('')
  const [name, setName] = useState('')
  const [values, setValues] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(model.native)
  const [error, setError] = useState<string | null>(null)
  const [round, setRound] = useState(0)
  const [verifyingId, setVerifyingId] = useState<string | null>(null)
  const [importing, setImporting] = useState(false)
  const [sources, setSources] = useState<NoLandSource[]>([])
  const [sourceId, setSourceId] = useState('')
  const [importError, setImportError] = useState<string | null>(null)
  const [reauthorizing, setReauthorizing] = useState<{ provider: Provider; schema: ProviderType } | null>(null)
  const [exported, setExported] = useState(false)
  const importRound = useRef(0)
  const selected = types.find((type) => type.kind === kind)
  const disabled = !model.ready || !!model.busy || loading || verifyingId !== null || importing
  useEffect(() => () => { importRound.current += 1 }, [])
  useEffect(() => {
    if (!model.native) return
    let disposed = false
    setLoading(true)
    setError(null)
    void api.providerTypes().then((next) => {
      if (disposed) return
      setTypes(next)
      setKind(next[0]?.kind ?? '')
      setName(next[0]?.name ?? '')
    }).catch((reason) => {
      if (!disposed) setError(safeError(reason))
    }).finally(() => { if (!disposed) setLoading(false) })
    return () => { disposed = true }
  }, [model.native, round])

  function connect(event: FormEvent) {
    event.preventDefault()
    if (!selected || disabled) return
    const fields: Record<string, string> = Object.create(null)
    const credentials: Record<string, string> = Object.create(null)
    for (const field of selected.fields) {
      const value = values[field.name] ?? ''
      if (!value && !field.required) continue
      if (field.credential) credentials[field.name] = value
      else fields[field.name] = value
    }
    // Start IPC synchronously, then immediately clear all transient input values.
    // No credentials are stored in the model, localStorage, logs, or query strings.
    const request = selected.auth === 'oauth'
      ? model.run('connect_oauth', {
        kind: selected.kind, name: name.trim(),
        clientId: fields.client_id, clientSecret: fields.client_secret,
        fields: Object.fromEntries(Object.entries(fields).filter(([key]) => !['client_id', 'client_secret'].includes(key))
          .map(([key, value]) => [key === 'prefix' ? 'folder' : key, value])),
      })
      : model.run('connect_provider', {
        kind: selected.kind, name: name.trim(), bucket: fields.bucket, prefix: fields.prefix,
        fields: Object.fromEntries(Object.entries(fields).filter(([key]) => !['bucket', 'prefix'].includes(key))),
        credentials: { type: selected.credentialType, value: credentials },
      })
    setValues({})
    void request
  }
  async function importNoLand() {
    if (disabled) return
    const round = ++importRound.current
    setValues({})
    setSources([]); setSourceId(''); setImportError(null); setImporting(true)
    try {
      const result = await model.run('discover_noland_import', {})
      if (result === undefined || importRound.current !== round) return
      const discovery = normalizeNoLandDiscovery(result)
      const selectedId = discovery.selectedId ?? (discovery.candidates.length === 1 ? discovery.candidates[0].id : undefined)
      if (selectedId) await model.run('import_noland', { sourceId: selectedId })
      else if (discovery.candidates.length > 1) {
        setSources(discovery.candidates)
        setSourceId(discovery.candidates[0].id)
      } else {
        setImportError('No No Land state.json was found in the approved locations.')
      }
    } catch (reason) {
      if (importRound.current === round) setImportError(safeError(reason))
    } finally {
      if (importRound.current === round) setImporting(false)
    }
  }
  async function importSelected() {
    if (disabled || !sources.some((source) => source.id === sourceId)) return
    const round = ++importRound.current
    const selectedId = sourceId
    setImporting(true)
    // Discovery IDs are native opaque references, never reconstructed paths.
    setSources([]); setSourceId('')
    try { await model.run('import_noland', { sourceId: selectedId }) }
    finally { if (importRound.current === round) setImporting(false) }
  }
  async function importAdvanced() {
    if (disabled) return
    setValues({}); setSources([]); setSourceId(''); setImportError(null)
    const stateFile = await model.pick(chooseNoLandState)
    if (stateFile) await model.run('import_noland', { stateFile })
  }
  async function verifyProvider(providerId: string) {
    if (disabled) return
    setVerifyingId(providerId)
    try { await model.run('verify_provider', { providerId }) }
    finally { setVerifyingId(null) }
  }
  function reauthorize(provider: Provider) {
    const schema = types.find((type) => type.kind === provider.kind)
    if (disabled || !schema || !['connected', 'error'].includes(provider.status)) return
    setValues({}); model.dismissNotice()
    if (schema.auth === 'oauth') void model.run('reauthorize_provider', { providerId: provider.id })
    else setReauthorizing({ provider, schema })
  }
  async function exportRecoveryKey(provider: Provider) {
    if (disabled) return
    setValues({}); setExported(false)
    const destination = await model.pick(chooseRecoveryDestination)
    if (!destination) return
    const result = await model.run('export_recovery_key', { providerId: provider.id, destination })
    if (result === undefined) return
    if (record(result)?.written === true && record(result)?.keyMaterialReturned === false) setExported(true)
    else model.reportError('The native recovery-key export receipt is unavailable. No key material is shown in QuickSave.')
  }

  if (reauthorizing) return <ReauthorizeDialog provider={reauthorizing.provider} schema={reauthorizing.schema} model={model}
    onClose={() => setReauthorizing(null)} />
  return <Dialog title="Connect providers" sheet onClose={onClose} busy={!!model.busy || verifyingId !== null || importing}>
    <p className="dialog-note">Credentials stay in the native vault; connections require native approval.</p>
    {model.notice && <InlineError message={model.notice} />}
    {exported && <p className="runtime-banner" role="status">Recovery-key file exported with native protection. Keep the external copy private and separate from your backups.</p>}
    {loading && <p className="empty-line" role="status">Loading provider types…</p>}
    {error && <InlineError message={error} onRetry={() => setRound((value) => value + 1)} />}
    {!model.native && <p className="empty-line">Open QuickSave desktop to connect a provider.</p>}
    {types.length > 0 && <form className="provider-form" onSubmit={connect} autoComplete="off">
      <label className="field">Cloud provider
        <select value={kind} disabled={disabled} onChange={(event) => {
          const type = types.find((entry) => entry.kind === event.target.value)
          setKind(event.target.value)
          setName(type?.name ?? '')
          setValues({})
        }}>{types.map((type) => <option key={type.kind} value={type.kind}>{type.name}</option>)}</select>
      </label>
      <label className="field">Connection name
        <input required maxLength={200} value={name} disabled={disabled} autoComplete="off"
          onChange={(event) => setName(event.target.value)} />
      </label>
      {selected?.fields.map((field) => <label className={`field ${field.type === 'toggle' ? 'field-toggle' : ''}`} key={`${kind}-${field.name}`}>{field.label}{!field.required && ' (optional)'}
        {field.type === 'select'
          ? <select value={values[field.name] ?? ''} required={field.required} disabled={disabled}
            onChange={(event) => setValues((previous) => ({ ...previous, [field.name]: event.target.value }))}>
            <option value="">Choose…</option>
            {field.options?.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select>
          : field.type === 'toggle' ? <input type="checkbox" checked={values[field.name] === 'true'} disabled={disabled}
            onChange={(event) => setValues((previous) => ({ ...previous, [field.name]: String(event.target.checked) }))} />
          : <input type={field.secret ? 'password' : field.type === 'number' ? 'number' : 'text'}
            value={values[field.name] ?? ''} required={field.required} disabled={disabled}
            maxLength={8_192} autoComplete="off" autoCapitalize="none" spellCheck={false}
            data-private={field.secret || field.type === 'password' ? 'true' : undefined}
            onChange={(event) => setValues((previous) => ({ ...previous, [field.name]: event.target.value }))} />}
      </label>)}
      <Button type="submit" icon={selected?.auth === 'oauth' ? 'external' : 'plus'} disabled={disabled || !selected}>
        {model.busy === 'connect_oauth' || model.busy === 'connect_provider' ? 'Awaiting native connection…'
          : selected?.auth === 'oauth' ? 'Continue with native OAuth' : 'Connect provider'}
      </Button>
    </form>}
    {!loading && !error && model.native && types.length === 0 && <p className="empty-line">No provider types are available from this native runtime.</p>}
    <section className="provider-import"><h3>Already use No Land?</h3>
      <Button variant="secondary" icon="download" disabled={disabled}
        onClick={() => { void importNoLand() }}>
        {importing ? 'Awaiting native import…' : 'Import No Land'}
      </Button>
      {importError && <InlineError message={importError} />}
      {sources.length > 1 && <div className="import-source-picker">
        <label className="field">No Land source
          <select disabled={disabled} value={sourceId} onChange={(event) => setSourceId(event.target.value)}>
            {sources.map((source) => <option key={source.id} value={source.id}>{source.label}</option>)}
          </select>
        </label>
        {sources.filter((source) => source.id === sourceId).map((source) => <details className="dependency-list" key={source.id}>
          <summary>Source details</summary>
          <p className="truncate muted" title={source.path}>{source.path}</p>
          {source.modifiedAt && <p className="muted">Modified {date(source.modifiedAt)}</p>}
          {source.profileCount !== undefined && <p className="muted">{number(source.profileCount)} profiles</p>}
        </details>)}
        <div className="row-actions">
          <Button variant="secondary" disabled={disabled} onClick={() => {
            importRound.current += 1; setSources([]); setSourceId('')
          }}>Cancel source selection</Button>
          <Button disabled={disabled || !sourceId} onClick={() => { void importSelected() }}>Import selected No Land source</Button>
        </div>
      </div>}
      <details className="dependency-list"><summary>Advanced import</summary>
        <Button variant="ghost" disabled={disabled} onClick={() => { void importAdvanced() }}>Choose state.json manually</Button>
      </details>
    </section>
    {(model.dashboard?.providers.length ?? 0) > 0 && <section className="connected-list">
      <h3>Your connections</h3>
      <ul>{model.dashboard?.providers.map((provider) => <li key={provider.id}>
        <div className="provider-copy"><strong className="truncate" title={provider.name}>{provider.name}</strong>
          <span>{provider.status}{provider.readOnly ? ' · Read-only' : ''}</span>
          {provider.error && <span className="error-text">{provider.error}</span>}
        </div>
        <div className="row-actions">
          {(provider.status === 'error' || provider.status === 'connecting') && <Button variant="secondary" icon="refresh"
            disabled={disabled} aria-busy={verifyingId === provider.id}
            onClick={() => { void verifyProvider(provider.id) }}>
            {verifyingId === provider.id ? 'Checking connection…' : 'Check connection'}
          </Button>}
          {(provider.status === 'connected' || provider.status === 'error') && <Button variant="secondary"
            disabled={disabled || !types.some((type) => type.kind === provider.kind)}
            onClick={() => reauthorize(provider)}>Reauthorize</Button>}
          <Button variant="ghost" disabled={disabled}
            onClick={() => { void exportRecoveryKey(provider) }}>Export recovery key</Button>
          <Button variant="ghost" disabled={disabled || provider.status === 'disconnected'}
            onClick={() => { void model.run('disconnect_provider', { providerId: provider.id }) }}>Disconnect</Button>
          {provider.readOnly && <Button variant="secondary" disabled={disabled || provider.status !== 'connected'}
            onClick={() => { void model.run('authorize_provider_writes', { providerId: provider.id }) }}>Enable uploads</Button>}
        </div>
      </li>)}</ul>
    </section>}
  </Dialog>
}
