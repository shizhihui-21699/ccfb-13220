import React from 'react'
import { actionBadge, shortOID, ruleLabel } from '../api.js'

export function Stat({ label, value, tone }) {
  return (
    <div className={`stat ${tone || ''}`}>
      <div className="v">{value}</div>
      <div className="k">{label}</div>
    </div>
  )
}

export function Badge({ tone, children }) {
  return <span className={`badge ${tone || 'muted'}`}>{children}</span>
}

export function FindingsTable({ findings, showCommit = true, emptyText = 'Nothing matched.' }) {
  if (!findings || findings.length === 0) {
    return <div className="body muted small">{emptyText}</div>
  }
  return (
    <div className="scroll">
      <table>
        <thead>
          <tr>
            {showCommit && <th style={{ width: 110 }}>Commit</th>}
            <th>Path</th>
            <th style={{ width: 150 }}>Rule</th>
            <th style={{ width: 160 }}>Match</th>
            <th style={{ width: 150 }}>Action</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <tr key={i}>
              {showCommit && <td className="mono faint">{f.commit ? shortOID(f.commit) : '—'}</td>}
              <td className="path">
                {f.path || <span className="faint">(commit message)</span>}
                {f.line > 0 && <span className="faint">:{f.line}</span>}
                {f.note && <div className="hint">{f.note}</div>}
              </td>
              <td><code>{ruleLabel(f.rule)}</code></td>
              <td className="mono faint">{f.preview || '—'}</td>
              <td><Badge tone={actionBadge(f.action)}>{f.action}</Badge></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function RefsTable({ refs }) {
  const changed = (refs || []).filter((r) => r.changed)
  if (changed.length === 0) {
    return <div className="body muted small">No refs would change.</div>
  }
  return (
    <div className="scroll">
      <table>
        <thead>
          <tr>
            <th>Ref</th>
            <th style={{ width: 120 }}>Old</th>
            <th style={{ width: 120 }}>New</th>
          </tr>
        </thead>
        <tbody>
          {changed.map((r) => (
            <tr key={r.name}>
              <td className="path">{r.name}</td>
              <td className="mono faint">{shortOID(r.old)}</td>
              <td className="mono">{shortOID(r.new)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function SignatureLossTable({ losses, emptyText = 'No signatures were lost.' }) {
  if (!losses || losses.length === 0) {
    return <div className="body muted small">{emptyText}</div>
  }
  return (
    <div className="scroll">
      <table>
        <thead>
          <tr>
            <th style={{ width: 80 }}>Kind</th>
            <th>Object</th>
            <th style={{ width: 110 }}>Was</th>
            <th style={{ width: 220 }}>Signer</th>
            <th style={{ width: 200 }}>Replacement</th>
          </tr>
        </thead>
        <tbody>
          {losses.map((l, i) => (
            <tr key={i}>
              <td><Badge tone={l.kind === 'tag' ? 'info' : 'muted'}>{l.kind}</Badge></td>
              <td className="path">
                {l.ref || shortOID(l.old_oid)}
                <div className="hint mono">{shortOID(l.old_oid)}</div>
              </td>
              <td><Badge tone={l.old_signature_status === 'valid' ? 'ok' : 'warn'}>{l.old_signature_status}</Badge></td>
              <td className="small">{l.identity || <span className="faint">unknown</span>}</td>
              <td className="mono">{shortOID(l.new_oid)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="body small muted" style={{ paddingTop: 0 }}>
        A signature covers the exact bytes of the object it signs, so a rewritten object cannot
        keep its signature. Re-sign the affected commits and tags after the rewrite if your
        policy requires signed history.
      </div>
    </div>
  )
}
