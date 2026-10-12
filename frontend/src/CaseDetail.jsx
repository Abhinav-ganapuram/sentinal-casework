import { useEffect, useRef, useState } from 'react'
import './Investigation.css'

export default function CaseDetail({ caseId, onClose }) {
  const [caseData, setCaseData] = useState(null)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [running, setRunning] = useState(false)
  const [investigationError, setInvestigationError] = useState('')
  const investigationRequest = useRef(null)

  useEffect(() => {
    const controller = new AbortController()

    async function loadCase() {
      try {
        const response = await fetch(
          `/api/cases/${encodeURIComponent(caseId)}`,
          { signal: controller.signal },
        )

        if (!response.ok) {
          throw new Error(`Could not load case (${response.status})`)
        }

        const data = await response.json()

        if (!controller.signal.aborted) {
          setCaseData(data)
        }
      } catch (err) {
        if (!controller.signal.aborted) {
          setError(err.message)
        }
      }
    }

    loadCase()

    return () => {
      controller.abort()
      investigationRequest.current?.abort()
    }
  }, [caseId])

  async function runInvestigation() {
    if (investigationRequest.current) return

    const controller = new AbortController()
    investigationRequest.current = controller

    setRunning(true)
    setInvestigationError('')
    setResult(null)

    try {
      const response = await fetch(
        `/api/cases/${encodeURIComponent(caseId)}/investigate`,
        {
          method: 'POST',
          signal: controller.signal,
        },
      )

      if (!response.ok) {
        throw new Error(`Investigation failed (${response.status})`)
      }

      const data = await response.json()

      if (data.case_id !== caseId) {
        throw new Error('The response belongs to a different case')
      }

      if (!controller.signal.aborted) {
        setResult(data)
      }
    } catch (err) {
      if (!controller.signal.aborted) {
        setInvestigationError(err.message)
      }
    } finally {
      if (investigationRequest.current === controller) {
        investigationRequest.current = null
      }

      if (!controller.signal.aborted) {
        setRunning(false)
      }
    }
  }

  const statusLabels = {
    needs_review: 'Human review required',
    no_detection: 'No detection triggered',
    step_limit: 'Step limit reached — review required',
  }

  return (
    <section className="detail-panel" aria-labelledby="detail-heading">
      <div className="section-heading">
        <div>
          <p className="eyebrow">{caseId} · SOURCE EVIDENCE</p>
          <h2 id="detail-heading">
            {caseData ? caseData.title : 'Case details'}
          </h2>
        </div>

        <button className="secondary-button" onClick={onClose}>
          Close case
        </button>
      </div>

      {error && <p role="alert">{error}</p>}

      {!caseData && !error && (
        <p role="status">Loading evidence…</p>
      )}

      {caseData && (
        <>
          <div className="investigation-controls">
            <div>
              <h3>Investigate this case</h3>
              <p className="muted">
                Scripted demo · Read-only tools · No model calls
              </p>
            </div>

            <button
              className="run-button"
              onClick={runInvestigation}
              disabled={running}
            >
              {running
                ? 'Investigating…'
                : result
                  ? 'Run demo again'
                  : 'Run demo investigation'}
            </button>
          </div>

          {running && (
            <p role="status">Running the scripted investigation…</p>
          )}

          {investigationError && (
            <div className="error-panel" role="alert">
              <p>{investigationError}</p>
              <p>Check the backend connection and try again.</p>
            </div>
          )}

          {result && (
            <section
              className="investigation-result"
              aria-labelledby="result-heading"
            >
              <div className="section-heading">
                <h3 id="result-heading">Investigation result</h3>
                <span className="badge">
                  {result.execution_mode === 'demo'
                    ? 'SCRIPTED DEMO'
                    : result.execution_mode}
                </span>
              </div>

              <p className="result-status" role="status">
                {statusLabels[result.status] ?? result.status}
              </p>

              <h4>Detection findings ({result.findings.length})</h4>

              {result.findings.length === 0 && (
                <p className="muted">
                  No configured detection rule matched this case.
                  This does not establish that all activity is safe.
                </p>
              )}

              {result.findings.map((finding, index) => (
                <article
                  className="finding-card"
                  key={`${finding.rule_id}-${index}`}
                >
                  <div className="finding-meta">
                    <span>{finding.rule_id}</span>
                    <span className="severity-label">
                      {finding.severity.toUpperCase()}
                    </span>
                  </div>
                  <h4>{finding.title}</h4>
                  <p>{finding.reason}</p>
                  <p className="evidence-reference">
                    Evidence: {finding.evidence_ids.join(', ')}
                  </p>
                </article>
              ))}

              <h4>Investigation steps ({result.trace.length})</h4>

              {result.trace.length === 0 && (
                <p className="muted">No follow-up lookups were performed.</p>
              )}

              <ol className="trace-list">
                {result.trace.map((step, index) => (
                  <li key={`${step.tool}-${index}`}>
                    <code>{step.tool}</code>
                    <p className="trace-query">{step.query}</p>
                    <p>{step.reason}</p>
                    <p className="evidence-reference">
                      {step.result_count} events: {
                        step.event_ids.length
                          ? step.event_ids.join(', ')
                          : 'None'
                      }
                    </p>
                  </li>
                ))}
              </ol>

              {result.finish_reason && (
                <div className="finish-note">
                  <h4>Completion note</h4>
                  <p>{result.finish_reason}</p>
                </div>
              )}

              {result.status === 'step_limit' && (
                <p className="muted">
                  The investigation stopped at its configured step limit.
                  Evidence collection may be incomplete.
                </p>
              )}
            </section>
          )}

          <h3 className="timeline-heading">Source timeline</h3>
          <p className="muted">
            {caseData.events.length} events · Timestamps shown in UTC
          </p>

          <div className="timeline-scroll">
            <table className="timeline-table">
              <caption className="visually-hidden">
                Source events for {caseId}
              </caption>
              <thead>
                <tr>
                  <th scope="col">Event</th>
                  <th scope="col">Time (UTC)</th>
                  <th scope="col">Action</th>
                  <th scope="col">Outcome</th>
                  <th scope="col">User</th>
                </tr>
              </thead>
              <tbody>
                {caseData.events.map((event) => (
                  <tr key={event.id}>
                    <td className="event-id">{event.id}</td>
                    <td>{new Date(event.timestamp).toISOString()}</td>
                    <td>{event.action}</td>
                    <td>{event.outcome}</td>
                    <td>{event.user}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <details className="raw-evidence">
            <summary>Inspect complete source events</summary>
            <pre>{JSON.stringify(caseData.events, null, 2)}</pre>
          </details>
        </>
      )}
    </section>
  )
}