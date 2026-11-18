// SPDX-License-Identifier: GPL-3.0-only
// Test-only: read the actual synthetic Rust fixtures, without building/running
// native code, IPC, providers, installed apps, No Land state or the credential vault.
// This deliberately supports only the literal constructs in those fixtures.
// Unsupported source changes fail tests instead of silently inventing new data.
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { record } from '../api'

export function backendSource(path: string): string {
  const source = readFileSync(resolve(process.cwd(), '../../', path), 'utf8')
  if (source.length > 1_048_576) throw new Error('Backend fixture source exceeds its test bound.')
  return source
}

function macroAfter(source: string, marker: string): string {
  const markerIndex = source.indexOf(marker)
  const macro = source.indexOf('json!(', markerIndex)
  if (markerIndex < 0 || macro < 0) throw new Error(`Actual backend fixture marker is missing: ${marker}`)
  const start = macro + 'json!('.length
  let depth = 1
  let quoted = false
  let escaped = false
  for (let index = start; index < source.length; index += 1) {
    const char = source[index]
    if (quoted) {
      if (escaped) escaped = false
      else if (char === '\\') escaped = true
      else if (char === '"') quoted = false
    } else if (char === '"') quoted = true
    else if (char === '(') depth += 1
    else if (char === ')' && --depth === 0) return source.slice(start, index)
  }
  throw new Error('Actual backend fixture JSON is unbalanced.')
}

function uuid(value: number): string {
  const hex = value.toString(16).padStart(32, '0')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

function literalJson(raw: string, variables: Record<string, unknown> = {}, index = 0): unknown {
  const numeric = (expression: string) => expression.split('+').reduce((sum, token) => {
    const text = token.trim()
    if (text !== 'index' && !/^\d+$/.test(text)) throw new Error('Unsupported Rust fixture arithmetic.')
    return sum + (text === 'index' ? index : Number(text))
  }, 0)
  let json = raw.replace(/if index==0 \{ None \} else \{ Some\(Uuid::from_u128\(index\)\) \}/g,
    JSON.stringify(index === 0 ? null : uuid(index)))
    .replace(/match index \{ 0=>"complete_application",1=>"personal_state",_=>"custom" \}/g,
      JSON.stringify(['complete_application', 'personal_state', 'custom'][index]))
    .replace(/format!\(("(?:\\.|[^"])*")\)/g, (_, quoted: string) =>
      JSON.stringify((JSON.parse(quoted) as string).replaceAll('{index}', String(index))))
    .replace(/Uuid::from_u128\(([\d\s+index]+)\)/g, (_, expression: string) => JSON.stringify(uuid(numeric(expression))))
    .replace(/("(?:\\.|[^"])*")\.repeat\((\d+)\)/g, (_, quoted: string, count: string) =>
      JSON.stringify((JSON.parse(quoted) as string).repeat(Number(count))))
    .replace(/index==(\d+)/g, (_, value: string) => String(index === Number(value)))
    .replace(/\b(\d+)\+index\b/g, (_, value: string) => String(Number(value) + index))
    .replace(/\bValue::Null\b/g, 'null')
  for (const [key, value] of Object.entries(variables)) {
    if (!/^[A-Za-z_]+$/.test(key)) throw new Error('Invalid test fixture binding.')
    json = json.replace(new RegExp(`([:\\[,]\\s*)${key}(?=\\s*[,}\\]])`, 'g'), (_, prefix: string) => prefix + JSON.stringify(value))
  }
  return JSON.parse(json.replace(/,\s*([}\]])/g, '$1')) as unknown
}

export function catalogBackendFixture(): Record<string, unknown> {
  const source = backendSource('crates/quicksave-service/src/catalog.rs')
  const fixture = source.slice(source.indexOf('fn fixture() -> Value {'), source.indexOf('fn query(view:'))
  const size = fixture.match(/let bundles\s*=\s*\(0\.\.(\d+)\)/)?.[1]
  if (!size || Number(size) > 100) throw new Error('Actual catalog fixture range is missing or oversized.')
  const rawBundle = macroAfter(fixture, 'let bundles')
  const bundles = Array.from({ length: Number(size) }, (_, index) => literalJson(rawBundle, {}, index))
  const document = record(literalJson(macroAfter(fixture, 'let mut document'), { bundles }))
  if (!document) throw new Error('Actual native catalog fixture is invalid.')
  return document
}

export function pendingBackendFixture(): Record<string, unknown> {
  const source = backendSource('crates/quicksave-service/src/catalog.rs')
  const test = source.slice(source.indexOf('fn pending_deletion_summaries_and_paged_exact_dependencies_keep_source_plan_identity()'))
  const planValue = test.match(/let plan = Uuid::from_u128\((\d+)\)/)?.[1]
  if (!planValue) throw new Error('Actual pending-deletion fixture plan is missing.')
  const dependent = literalJson(macroAfter(test, 'let dependent ='))
  const requested = literalJson(macroAfter(test, 'let requested ='))
  const plans = literalJson(macroAfter(test, 'document["pendingDeletions"] ='), {
    plan: uuid(Number(planValue)), dependent, requested,
  })
  const plan = Array.isArray(plans) && record(plans[0])
  if (!plan) throw new Error('Actual pending-deletion fixture is invalid.')
  // Decode the actual summary projection, not a handwritten substitute for it.
  const projection = source.slice(source.indexOf('fn pending_summary('), source.indexOf('fn validate_pending('))
  let raw = macroAfter(projection, '\n    Ok(json!(')
  raw = raw.replace(/plan\["targets"\]\.as_array\(\)\.map\(Vec::len\)/g, String((plan.targets as unknown[]).length))
    .replace(/plan\["dependencies"\]\.as_array\(\)\.map\(Vec::len\)/g, String((plan.dependencies as unknown[]).length))
    .replace(/plan\["dependencies"\]\.is_array\(\)/g, String(Array.isArray(plan.dependencies)))
    .replace(/plan\["names"\]\.as_array\(\)\.into_iter\(\)\.flatten\(\)\.take\(16\)\.collect::<Vec<_>>\(\)/g,
      JSON.stringify((plan.names as unknown[]).slice(0, 16)))
    .replace(/plan\["([A-Za-z]+)"\]/g, (_, key: string) => JSON.stringify(plan[key]))
    .replace(/^\s*\/\/[^\n]*$/gm, '')
  const summary = record(literalJson(raw))
  if (!summary) throw new Error('Actual pending-deletion summary is invalid.')
  return summary
}
