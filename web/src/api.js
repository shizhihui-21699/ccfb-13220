export async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  let data = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = { error: text }
  }
  if (!res.ok) {
    const msg = (data && (data.error || data.message)) || `HTTP ${res.status}`
    const err = new Error(msg)
    err.status = res.status
    throw err
  }
  return data
}

export function shortOID(oid, n = 10) {
  if (!oid) return ''
  return oid.length > n ? oid.slice(0, n) : oid
}

export function relTime(iso) {
  if (!iso) return ''
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return ''
  const d = Math.max(0, Date.now() - t)
  const mins = Math.round(d / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.round(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.round(hrs / 24)}d ago`
}

export function ruleLabel(rule) {
  if (!rule) return ''
  if (rule.startsWith('preset:')) return rule.slice(7)
  if (rule.startsWith('path:')) return rule.slice(5)
  return rule
}

export const ACTION_LABEL = {
  'delete-path': 'path removed',
  'delete-content': 'content removed',
  'message-redact': 'message redacted',
  skipped: 'skipped (too large)',
  'purge-whole-file': 'whole file purged',
  survived: 'survived',
  'backup-only': 'backup only',
}

export function actionBadge(action) {
  switch (action) {
    case 'delete-path':
    case 'purge-whole-file':
      return 'danger'
    case 'delete-content':
      return 'danger'
    case 'message-redact':
      return 'warn'
    case 'skipped':
      return 'warn'
    case 'survived':
      return 'danger'
    default:
      return 'muted'
  }
}
