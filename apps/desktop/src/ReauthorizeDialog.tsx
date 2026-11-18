// SPDX-License-Identifier: GPL-3.0-only
import { useState, type FormEvent } from 'react'
import type { Provider, ProviderType } from './api'
import type { QuickSave } from './useQuickSave'
import { Button, Dialog, InlineError } from './ui'

export function ReauthorizeDialog({ provider, schema, model, onClose }: {
  provider: Provider; schema: ProviderType; model: QuickSave; onClose: () => void
}) {
  const [values, setValues] = useState<Record<string, string>>({})
  const fields = schema.fields.filter((field) => field.credential)
  const disabled = !model.ready || !!model.busy || provider.status === 'disconnected'
  async function submit(event: FormEvent) {
    event.preventDefault()
    if (disabled || schema.auth !== 'credentials') return
    const credentials: Record<string, string> = Object.create(null)
    for (const field of fields) {
      const value = values[field.name] ?? ''
      if (value || field.required) credentials[field.name] = value
    }
    const request = model.run('reauthorize_provider', {
      providerId: provider.id, credentials: { type: schema.credentialType, value: credentials },
    })
    setValues({})
    if (await request !== undefined) onClose()
  }
  return <Dialog title="Reauthorize provider" onClose={onClose} busy={!!model.busy}>
    <strong className="truncate" title={provider.name}>{provider.name}</strong>
    <p className="dialog-note">Replace credentials for this existing {schema.name} connection only. Its kind, bucket, folder, roots and client configuration cannot be changed here. Existing autosave grants are revoked; verify the new connection before enabling autosave again.</p>
    {provider.readOnly && <p className="muted">This imported connection remains read-only after reauthorization. Uploads require a separate native grant.</p>}
    {model.notice && <InlineError message={model.notice} />}
    <form className="provider-form" autoComplete="off" onSubmit={(event) => { void submit(event) }}>
      {fields.map((field) => <label className="field" key={field.name}>{field.label}{!field.required && ' (optional)'}
        {field.type === 'select' ? <select value={values[field.name] ?? ''} required={field.required} disabled={disabled}
          onChange={(event) => setValues((previous) => ({ ...previous, [field.name]: event.target.value }))}>
          <option value="">Choose…</option>
          {field.options?.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select> : <input type="password" value={values[field.name] ?? ''} required={field.required} disabled={disabled}
          maxLength={8_192} autoComplete="off" autoCapitalize="none" spellCheck={false} data-private="true"
          onChange={(event) => setValues((previous) => ({ ...previous, [field.name]: event.target.value }))} />}
      </label>)}
      {!fields.length && <p className="error-text">Native credential fields are unavailable for this provider. Reauthorization cannot be submitted.</p>}
      <div className="modal-actions"><Button variant="secondary" onClick={onClose} disabled={!!model.busy}>Cancel</Button>
        <Button type="submit" disabled={disabled || !fields.length}>Reauthorize with native confirmation</Button></div>
    </form>
  </Dialog>
}
