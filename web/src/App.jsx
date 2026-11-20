import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api.js'
import { Badge, FindingsTable, RefsTable, SignatureLossTable, Stat } from './components/Tables.jsx'

const EXAMPLE_RULES = [
  { kind: 'path', value: 'exports/*.csv', note: 'customer data export' },
  { kind: 'preset', value: 'aws_access_key', note: 'production access key' },
  { kind: 'preset', value: 'private_key' },
]

const EMPTY_SPEC = { rules: EXAMPLE_RULES, scan_commit_messages: false, purge_whole_file: true }

function useStored(key, initial) {
  const [v, setV] = useState(() => {
    try {
      const raw = localStorage.getItem(key)
      return raw ? JSON.parse(raw) : initial
    } catch {
      return initial
    }
  })
  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(v))
    } catch {
      /* storage may be unavailable; the page still works */
    }
  }, [key, v])
  return [v, setV]
}

export default function App() {
  const [health, setHealth] = useState(null)
  const [repos, setRepos] = useState([])
  const [repo, setRepo] = useState(null)
  const [spec, setSpec] = useStored('hs.spec', EMPTY_SPEC)
  const [specText, setSpecText] = useState(() => JSON.stringify(EMPTY_SPEC, null, 2))
  const [mode, setMode] = useState('form')
  const [presets, setPresets] = useState([])
  const [plan, setPlan] = useState(null)
  const [report, setReport] = useState(null)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [confirmText, setConfirmText] = useState('')
  const [resetWorktree, setResetWorktree] = useState(true)
  const [verification, setVerification] = useState(null)
  const [pruneResult, setPruneResult] = useState(null)
  const [notice, setNotice] = useState(null)
  const [remote, setRemote] = useState('')

  useEffect(() => {
    api('GET', '/api/health').then(setHealth).catch((e) => setError(e.message))
    api('GET', '/api/repos').then((d) => setRepos(d.repos || [])).catch((e) => setError(e.message))
    api('GET', '/api/presets').then((d) => setPresets(d.presets || [])).catch(() => {})
  }, [])

  const step = report ? (verification ? (pruneResult ? 4 : 3) : 2) : plan ? 1 : 0

  function resetFromPlan() {
    setPlan(null)
    setReport(null)
    setVerification(null)
    setPruneResult(null)
    setNotice(null)
    setConfirmText('')
    setError('')
  }

  async function openRepo(r) {
    setError('')
    try {
      const d = await api('POST', '/api/repo/open', { path: r.path })
      setRepo(d.repo)
      resetFromPlan()
    } catch (e) {
      setError(e.message)
    }
  }

  function currentSpec() {
    if (mode === 'json') {
      const parsed = JSON.parse(specText)
      return parsed
    }
    return spec
  }

  async function doPlan() {
    setBusy('plan')
    setError('')
    resetFromPlan()
    try {
      const parsedSpec = currentSpec()
      const d = await api('POST', '/api/plan', { repo: repo.path, spec: parsedSpec })
      setPlan(d)
      setSpec(parsedSpec)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy('')
    }
  }

  async function doRun() {
    setBusy('run')
    setError('')
    try {
      const d = await api('POST', '/api/run', {
        plan_id: plan.plan_id,
        confirm: confirmText,
        reset_worktree: resetWorktree,
      })
      setReport(d.report)
      setPlan({ ...plan, sensitive: d.sensitive })
      setConfirmText('')
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy('')
    }
  }

  async function doVerify() {
    setBusy('verify')
    setError('')
    try {
      const d = await api('POST', '/api/verify', {
        repo: repo.path,
        spec: currentSpec(),
        sensitive: plan.sensitive,
      })
      setVerification(d)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy('')
    }
  }

  async function doPrune() {
    setBusy('prune')
    setError('')
    try {
      const d = await api('POST', '/api/prune', { repo: repo.path, confirm: 'PRUNE' })
      setPruneResult(d)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy('')
    }
  }

  async function doNotify() {
    setBusy('notify')
    setError('')
    try {
      const d = await api('POST', '/api/notify', {
        repo: repo.path,
        remote,
        plan_id: plan?.plan_id,
      })
      setNotice(d)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy('')
    }
  }

  const activeReport = report || plan?.report
  const stats = useMemo(() => computeStats(activeReport), [activeReport])

  return (
    <div className="app">
      <div className="topbar">
        <div className="brand">
          <span className="dot">●</span> historyscrub
          <small>rewrite git history and prove the data is gone</small>
        </div>
        <div className="spacer" />
        {health && (
          <div className="row small">
            <Badge tone={health.allow_run ? 'ok' : 'warn'}>
              {health.allow_run ? 'mutations enabled' : 'read-only server'}
            </Badge>
            <span className="faint mono">{health.root}</span>
          </div>
        )}
      </div>

      <div className="layout">
        <aside className="sidebar">
          <div className="section">
            <h2>Repositories</h2>
            {repos.length === 0 && <div className="small muted">No repository found under the server root.</div>}
            {repos.map((r) => (
              <button
                key={r.path}
                className={`repo-item ${repo?.path === r.path ? 'active' : ''}`}
                onClick={() => openRepo(r)}
              >
                <div className="name">{r.name}</div>
                <div className="meta">
                  {r.commits} commits · {r.refs} refs
                  {r.dirty > 0 && <span className="warn-text"> · {r.dirty} dirty</span>}
                </div>
                <div className="meta mono">{r.head || 'no HEAD'}</div>
              </button>
            ))}
          </div>

          {repo && (
            <div className="section">
              <h2>Selection</h2>
              <dl className="kv small">
                <dt>repo</dt>
                <dd className="mono">{repo.name}</dd>
                <dt>HEAD</dt>
                <dd className="mono">{repo.head}</dd>
                <dt>objects</dt>
                <dd>{repo.object_format}</dd>
              </dl>
            </div>
          )}

          <div className="section">
            <h2>Workflow</h2>
            <ol className="small muted" style={{ paddingLeft: 18, margin: 0, lineHeight: 1.9 }}>
              <li>Select a repository</li>
              <li>Describe what to remove</li>
              <li>Preview the plan</li>
              <li>Rewrite, verify, prune</li>
              <li>Send the re-clone notice</li>
            </ol>
          </div>
        </aside>

        <main className="main">
          {error && <div className="banner danger">{error}</div>}

          <div className="steps">
            {['Repository', 'Scope', 'Preview', 'Rewrite & verify'].map((label, i) => (
              <div key={label} className={`step ${step === i ? 'active' : step > i ? 'done' : ''}`}>
                <span className="n">{step > i ? '✓' : i + 1}</span>
                {label}
              </div>
            ))}
          </div>

          {!repo && (
            <div className="card">
              <header><h3>Start here</h3></header>
              <div className="body">
                <p className="muted" style={{ marginTop: 0 }}>
                  Pick a repository on the left. The repository browser only looks inside the
                  directory the server was started with; paths outside it are refused.
                </p>
                <p className="small faint">
                  Deleting a file in a new commit does not remove it. Every commit that ever held
                  it has to be rewritten, which this tool does for all branches and tags at once.
                </p>
              </div>
            </div>
          )}

          {repo && (
            <>
              <ScopeEditor
                spec={spec}
                setSpec={setSpec}
                mode={mode}
                setMode={setMode}
                specText={specText}
                setSpecText={setSpecText}
                presets={presets}
                onPlan={doPlan}
                busy={busy === 'plan'}
                canMutate={health?.allow_run}
                plan={plan}
              />

              {plan && (
                <PlanView plan={plan} repo={repo} />
              )}

              {plan && !report && (
                <RunPanel
                  plan={plan}
                  confirmText={confirmText}
                  setConfirmText={setConfirmText}
                  resetWorktree={resetWorktree}
                  setResetWorktree={setResetWorktree}
                  onRun={doRun}
                  busy={busy === 'run'}
                  allowRun={health?.allow_run}
                />
              )}

              {report && (
                <ReportView report={report} stats={stats} />
              )}

              {report && (
                <VerifyPanel
                  verification={verification}
                  onVerify={doVerify}
                  busy={busy === 'verify'}
                  onPrune={doPrune}
                  pruneBusy={busy === 'prune'}
                  pruneResult={pruneResult}
                  allowRun={health?.allow_run}
                />
              )}

              {report && (
                <NotifyPanel
                  notice={notice}
                  onNotify={doNotify}
                  busy={busy === 'notify'}
                  remote={remote}
                  setRemote={setRemote}
                  repoName={repo.name}
                />
              )}
            </>
          )}
        </main>
      </div>
    </div>
  )
}

// The API returns stats alongside the plan, but not alongside a run report, so
// derive them from the report itself and keep one shape for both views.
function computeStats(report) {
  if (!report) return {}
  const affected = new Set()
  for (const f of report.findings || []) {
    if (f.commit) affected.add(f.commit)
  }
  const refsRewritten = (report.refs || []).filter((r) => r.changed).length
  return {
    findings: (report.findings || []).length,
    commits_affected: affected.size,
    refs_rewritten: refsRewritten,
    signature_losses: (report.signature_losses || []).length,
  }
}

function ScopeEditor({ spec, setSpec, mode, setMode, specText, setSpecText, presets, onPlan, busy, canMutate, plan }) {
  function updateRule(i, patch) {
    const rules = spec.rules.map((r, j) => (j === i ? { ...r, ...patch } : r))
    setSpec({ ...spec, rules })
  }
  function addRule(kind) {
    setSpec({ ...spec, rules: [...spec.rules, { kind, value: kind === 'preset' ? presets[0]?.name || '' : '' }] })
  }
  function removeRule(i) {
    setSpec({ ...spec, rules: spec.rules.filter((_, j) => j !== i) })
  }

  return (
    <div className="card">
      <header>
        <h3>What to remove</h3>
        <div className="row">
          <button className={mode === 'form' ? 'primary' : ''} onClick={() => setMode('form')}>Form</button>
          <button className={mode === 'json' ? 'primary' : ''} onClick={() => setMode('json')}>JSON</button>
        </div>
      </header>
      <div className="body">
        {mode === 'form' ? (
          <>
            {spec.rules.map((r, i) => (
              <div className="rule-row" key={i}>
                <select value={r.kind} onChange={(e) => updateRule(i, { kind: e.target.value })}>
                  <option value="path">path</option>
                  <option value="literal">literal</option>
                  <option value="regex">regex</option>
                  <option value="preset">preset</option>
                </select>
                {r.kind === 'preset' ? (
                  <select value={r.value} onChange={(e) => updateRule(i, { value: e.target.value })}>
                    {presets.map((p) => (
                      <option key={p.name} value={p.name}>{p.name} — {p.description}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    value={r.value}
                    placeholder={
                      r.kind === 'path' ? 'exports/*.csv  or  **/*.pem'
                        : r.kind === 'literal' ? 'exact string to find'
                        : 'regular expression'
                    }
                    onChange={(e) => updateRule(i, { value: e.target.value })}
                  />
                )}
                <input
                  type="text"
                  value={r.note || ''}
                  placeholder="note (shows in the report)"
                  onChange={(e) => updateRule(i, { note: e.target.value })}
                />
                <button className="ghost" title="Remove rule" onClick={() => removeRule(i)}>✕</button>
              </div>
            ))}
            <div className="row" style={{ marginTop: 4 }}>
              <button onClick={() => addRule('path')}>+ path</button>
              <button onClick={() => addRule('literal')}>+ literal</button>
              <button onClick={() => addRule('regex')}>+ regex</button>
              <button onClick={() => addRule('preset')}>+ preset</button>
            </div>
            <div className="row" style={{ marginTop: 14 }}>
              <label className="small row" style={{ gap: 6 }}>
                <input
                  type="checkbox"
                  checked={spec.purge_whole_file !== false}
                  onChange={(e) => setSpec({ ...spec, purge_whole_file: e.target.checked })}
                />
                remove every version of a matched path
              </label>
              <label className="small row" style={{ gap: 6 }}>
                <input
                  type="checkbox"
                  checked={!!spec.scan_commit_messages}
                  onChange={(e) => setSpec({ ...spec, scan_commit_messages: e.target.checked })}
                />
                also scrub commit messages
              </label>
            </div>
            <div className="hint">
              Globs support <code>**</code>, <code>*</code> and <code>?</code>. A pattern without a
              slash matches at any depth, so <code>*.pem</code> covers <code>keys/prod.pem</code>.
            </div>
          </>
        ) : (
          <textarea rows={14} value={specText} onChange={(e) => setSpecText(e.target.value)} spellCheck={false} />
        )}
        <div className="row" style={{ marginTop: 14 }}>
          <button className="primary" onClick={onPlan} disabled={busy}>
            {busy ? <span className="spinner" /> : null} {busy ? ' analysing…' : 'Preview plan'}
          </button>
          <span className="small faint">
            Planning writes nothing. It lists every match and every ref that would change.
          </span>
        </div>
        {!canMutate && (
          <div className="banner warn" style={{ marginTop: 12, marginBottom: 0 }}>
            This server is read-only: you can plan and inspect, but rewrite and prune are
            disabled. Restart it with <code>-allow-run</code> to enable them.
          </div>
        )}
      </div>
    </div>
  )
}

function PlanView({ plan, repo }) {
  const r = plan.report
  return (
    <>
      <div className="card">
        <header>
          <h3>Plan preview</h3>
          <Badge tone="info">nothing written yet</Badge>
        </header>
        <div className="body">
          <div className="stats">
            <Stat label="findings" value={plan.stats.findings} tone="danger" />
            <Stat label="commits affected" value={plan.stats.commits_affected} />
            <Stat label="refs to rewrite" value={plan.stats.refs_rewritten} tone="warn" />
            <Stat label="signatures lost" value={plan.stats.signature_losses} tone={plan.stats.signature_losses ? 'warn' : ''} />
            <Stat label="commits scanned" value={r.commits_scanned} />
          </div>
          {r.warnings && r.warnings.length > 0 && (
            <div className="banner warn" style={{ marginTop: 14 }}>
              Before you rewrite:
              <ul>{r.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <header><h3>Findings</h3><span className="small muted">{plan.stats.findings} entries</span></header>
        <div className="body flush">
          <FindingsTable findings={r.findings} />
        </div>
      </div>

      <div className="card">
        <header><h3>Refs that change</h3></header>
        <div className="body flush"><RefsTable refs={r.refs} /></div>
      </div>

      <div className="card">
        <header>
          <h3>Signatures that cannot survive</h3>
          <span className="small muted">{r.signature_losses?.length || 0} affected</span>
        </header>
        <div className="body flush"><SignatureLossTable losses={r.signature_losses} /></div>
      </div>
    </>
  )
}

function RunPanel({ plan, confirmText, setConfirmText, resetWorktree, setResetWorktree, onRun, busy, allowRun }) {
  const ok = confirmText === 'REWRITE'
  return (
    <div className="card" style={{ borderColor: '#4a2329' }}>
      <header style={{ borderColor: '#4a2329' }}>
        <h3 className="danger-text">Rewrite history</h3>
        <Badge tone="danger">destructive</Badge>
      </header>
      <div className="body">
        <p style={{ marginTop: 0 }} className="small">
          This rewrites every branch and tag listed above. Commit ids change, so everyone with a
          clone must re-clone. Backup refs are created first under{' '}
          <code>refs/historyscrub/</code>, so the old objects stay recoverable until you prune.
        </p>
        <label className="small row" style={{ gap: 6, marginBottom: 10 }}>
          <input type="checkbox" checked={resetWorktree} onChange={(e) => setResetWorktree(e.target.checked)} />
          update the working tree afterwards (<code>git reset --hard HEAD</code>)
        </label>
        <div className="field">
          <label>Type REWRITE to confirm</label>
          <input
            type="text"
            value={confirmText}
            onChange={(e) => setConfirmText(e.target.value)}
            placeholder="REWRITE"
            style={{ maxWidth: 260 }}
          />
        </div>
        <button className="danger" disabled={!ok || busy || !allowRun} onClick={onRun}>
          {busy ? <span className="spinner" /> : null} {busy ? ' rewriting…' : 'Rewrite branches and tags'}
        </button>
      </div>
    </div>
  )
}

function ReportView({ report, stats }) {
  return (
    <>
      <div className="banner ok">
        Rewrite complete. {stats.refs_rewritten} ref(s) moved; the old objects are reachable only
        through the backup refs until you prune.
        {report.backup_manifest && (
          <div className="small mono" style={{ marginTop: 6 }}>backup manifest: {report.backup_manifest}</div>
        )}
      </div>
      <div className="card">
        <header><h3>What changed</h3></header>
        <div className="body">
          <div className="stats">
            <Stat label="commits rewritten" value={report.commits_rewritten} tone="warn" />
            <Stat label="commits unchanged" value={report.commits_unchanged} />
            <Stat label="refs moved" value={stats.refs_rewritten} tone="danger" />
            <Stat label="signatures lost" value={stats.signature_losses} tone={stats.signature_losses ? 'warn' : 'ok'} />
          </div>
          {report.warnings && report.warnings.length > 0 && (
            <div className="banner warn" style={{ marginTop: 14 }}>
              <ul style={{ margin: 0 }}>{report.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
            </div>
          )}
        </div>
      </div>
      <div className="card">
        <header><h3>Refs</h3></header>
        <div className="body flush"><RefsTable refs={report.refs} /></div>
      </div>
      <div className="card">
        <header><h3>Signatures lost in the rewrite</h3></header>
        <div className="body flush"><SignatureLossTable losses={report.signature_losses} /></div>
      </div>
    </>
  )
}

function VerifyPanel({ verification, onVerify, busy, onPrune, pruneBusy, pruneResult, allowRun }) {
  return (
    <div className="card">
      <header>
        <h3>Verify and prune</h3>
        <div className="row">
          <button onClick={onVerify} disabled={busy}>
            {busy ? <span className="spinner" /> : null} {busy ? ' scanning…' : 'Verify from objects'}
          </button>
          <button
            className="danger"
            onClick={onPrune}
            disabled={pruneBusy || !allowRun || !verification?.passed}
            title={!verification?.passed ? 'Verify first' : ''}
          >
            {pruneBusy ? <span className="spinner" /> : null} {pruneBusy ? ' pruning…' : 'Delete backups and prune'}
          </button>
        </div>
      </header>
      <div className="body">
        {!verification && (
          <p className="small muted" style={{ margin: 0 }}>
            Verification re-scans every object reachable from the live refs and checks that the
            sensitive objects are gone or reachable only through backups. Run it before pruning.
          </p>
        )}
        {verification && (
          <>
            <div className={`banner ${verification.passed ? 'ok' : 'danger'}`}>
              {verification.passed
                ? 'PASS — no sensitive object is reachable from a live ref, and no reachable blob matches the rules.'
                : `FAIL — ${verification.still_reachable} object(s) still reachable from live refs, ${verification.content_rescan?.hits?.length || 0} content hit(s).`}
            </div>
            <div className="stats">
              <Stat label="objects checked" value={verification.objects?.length || 0} />
              <Stat label="removed from object db" value={verification.removed_from_object_db} tone="ok" />
              <Stat label="backup-only" value={verification.backup_only} tone={verification.backup_only ? 'warn' : ''} />
              <Stat label="still reachable" value={verification.still_reachable} tone={verification.still_reachable ? 'danger' : 'ok'} />
              <Stat label="blobs rescanned" value={verification.content_rescan?.blobs_scanned || 0} />
            </div>
            {verification.objects?.length > 0 && (
              <details style={{ marginTop: 14 }}>
                <summary>Per-object results</summary>
                <div className="scroll" style={{ maxHeight: 300 }}>
                  <table>
                    <thead><tr><th>Object</th><th>Kind</th><th>Path</th><th>Status</th></tr></thead>
                    <tbody>
                      {verification.objects.map((o) => (
                        <tr key={o.oid}>
                          <td className="mono faint">{o.oid.slice(0, 12)}</td>
                          <td>{o.kind}</td>
                          <td className="path small">{(o.paths || []).join(', ') || '—'}</td>
                          <td>
                            <Badge tone={o.status === 'reachable' ? 'danger' : o.status === 'backup-only' ? 'warn' : 'ok'}>
                              {o.status}
                            </Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </details>
            )}
            {verification.content_rescan?.hits?.length > 0 && (
              <div className="banner danger" style={{ marginTop: 12 }}>
                Still reachable:
                <FindingsTable findings={verification.content_rescan.hits} showCommit={true} />
              </div>
            )}
            {verification.notes?.length > 0 && (
              <ul className="small muted" style={{ marginBottom: 0 }}>
                {verification.notes.map((n, i) => <li key={i}>{n}</li>)}
              </ul>
            )}
          </>
        )}
        {pruneResult && (
          <div className="banner ok" style={{ marginTop: 14 }}>
            Pruned. Objects: {pruneResult.objects_before} → {pruneResult.objects_after}; removed{' '}
            {pruneResult.removed_backup_refs} backup ref(s). Run verify again to confirm the objects
            are gone from the object database.
          </div>
        )}
      </div>
    </div>
  )
}

function NotifyPanel({ notice, onNotify, busy, remote, setRemote, repoName }) {
  const [copied, setCopied] = useState('')
  function copy(text, what) {
    navigator.clipboard?.writeText(text).then(
      () => { setCopied(what); setTimeout(() => setCopied(''), 1500) },
      () => setCopied('failed')
    )
  }
  return (
    <div className="card">
      <header>
        <h3>Collaborator notice</h3>
        <button onClick={onNotify} disabled={busy}>
          {busy ? <span className="spinner" /> : null} {busy ? ' composing…' : 'Generate re-clone instructions'}
        </button>
      </header>
      <div className="body">
        <div className="field">
          <label>Remote URL (used in the clone command)</label>
          <input type="text" value={remote} onChange={(e) => setRemote(e.target.value)} placeholder={`git@example.com:${repoName}.git`} />
        </div>
        {!notice && (
          <p className="small muted" style={{ margin: 0 }}>
            Produces the message to send everyone: why pulling will not help, and the exact steps
            to re-clone without dragging the old objects back.
          </p>
        )}
        {notice && (
          <>
            <div className="row between" style={{ marginBottom: 8 }}>
              <strong>{notice.subject}</strong>
              <div className="row">
                <button onClick={() => copy(notice.subject, 'subject')}>{copied === 'subject' ? 'copied' : 'copy subject'}</button>
                <button className="primary" onClick={() => copy(notice.body, 'body')}>{copied === 'body' ? 'copied' : 'copy message'}</button>
              </div>
            </div>
            <pre className="notice">{notice.body}</pre>
            <details style={{ marginTop: 12 }}>
              <summary>Maintainer checklist (not part of the message)</summary>
              {notice.checklist.map((c, i) => (
                <div className="checkline" key={i}>
                  <span className="box">☐</span>
                  <span>{c}</span>
                </div>
              ))}
            </details>
          </>
        )}
      </div>
    </div>
  )
}
