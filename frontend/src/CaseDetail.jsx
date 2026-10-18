
import { useEffect, useRef, useState } from 'react'
import InvestigationHistory from './InvestigationHistory'
import './Investigation.css'
import IncidentReport from './IncidentReport'
import AnalystReview from './AnalystReview'
import AINarrative from './AINarrative'

export default function CaseDetail({ caseId, onClose }) {
  const [caseData, setCaseData] = useState(null)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [resultError, setResultError] = useState('')
  const [historyVersion, setHistoryVersion] = useState(0)
  const [mode, setMode] = useState('demo')

  const resultRequest = useRef(null)

  useEffect(() => {
    const controller = new AbortController()

    setCaseData(null)
    setError('')
    setResult(null)
    setResultError('')

    async function loadCase() {
      try {
        const response = await fetch(
          `/api/cases/${encodeURIComponent(caseId)}`,
          { signal: controller.signal },
        )

        if (!response.ok) {
          throw new Error(
            `Could not load case (${response.status})`,
          )
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
      resultRequest.current?.abort()
    }
  }, [caseId])

  async function requestResult(path, method, body = null) {
    if (resultRequest.current) return

    const controller = new AbortController()
    resultRequest.current = controller

    setBusy(true)
    setResultError('')
    setResult(null)

    try {
      const response = await fetch(path, {
        method,
        signal: controller.signal,
        ...(body !== null && {
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(body),
        }),
      })

      if (!response.ok) {
        let message = `Request failed (${response.status})`

        try {
          const problem = await response.json()

          if (typeof problem.detail === 'string') {
            message = problem.detail
          }
        } catch {
          // Preserve the HTTP status message.
        }

        throw new Error(message)
      }

      const data = await response.json()

      if (data.case_id !== caseId) {
        throw new Error(
          'The response belongs to a different case',
        )
      }

      if (!controller.signal.aborted) {
        setResult(data)

        if (method === 'POST') {
          setHistoryVersion(
            (version) => version + 1,
          )
        }
      }
    } catch (err) {
      if (!controller.signal.aborted) {
        setResultError(err.message)
      }
    } finally {
      if (resultRequest.current === controller) {
        resultRequest.current = null
      }

      if (!controller.signal.aborted) {
        setBusy(false)
      }
    }
  }

  function runInvestigation() {
    return requestResult(
      `/api/cases/${encodeURIComponent(caseId)}/investigate`,
      'POST',
      { mode },
    )
  }

  function openSavedRun(investigationId) {
    return requestResult(
      `/api/investigations/${encodeURIComponent(investigationId)}`,
      'GET',
    )
  }

  const statusLabels = {
    needs_review: 'Human review required',
    no_detection: 'No detection triggered',
    step_limit: 'Step limit reached — review required',
    agent_error: 'AI investigation stopped — human review required',
  }

  return (
    <section
      className="detail-panel"
      aria-labelledby="detail-heading"
    >
      <div className="section-heading">
        <div>
          <p className="eyebrow">
            {caseId} · SOURCE EVIDENCE
          </p>

          <h2 id="detail-heading">
            {caseData
              ? caseData.title
              : 'Case details'}
          </h2>
        </div>

        <button
          className="secondary-button"
          onClick={onClose}
        >
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
                Evidence-backed · Read-only investigation
              </p>
            </div>

            <div className="mode-controls">
              <label htmlFor="investigation-mode">
                Investigation mode
              </label>

              <select
                id="investigation-mode"
                value={mode}
                onChange={(event) =>
                  setMode(event.target.value)
                }
                disabled={busy}
              >
                <option value="demo">
                  Scripted demo
                </option>

                <option value="gemini">
                  Live AI — GEMINI
                </option>
              </select>

              <button
                className="run-button"
                onClick={runInvestigation}
                disabled={busy}
              >
                {busy
                  ? 'Investigating...'
                  : mode === 'demo'
                    ? 'Run demo investigation'
                    : 'Run AI investigation'}
              </button>
            </div>
          </div>

          <InvestigationHistory
            key={`${caseId}-${historyVersion}`}
            caseId={caseId}
            onOpen={openSavedRun}
            disabled={busy}
            selectedId={result?.investigation_id}
          />

          {busy && (
            <p role="status">
              Loading investigation result…
            </p>
          )}

          {resultError && (
            <div
              className="error-panel"
              role="alert"
            >
              <p>{resultError}</p>
              <p>
                Check the backend configuration
                and try again.
              </p>
            </div>
          )}

          {result && (
            <>
            <section
              className="investigation-result"
              aria-labelledby="result-heading"
            >
              <div className="section-heading">
                <h3 id="result-heading">
                  Investigation result
                </h3>

                <span className="badge">
                  {result.execution_mode === 'demo'
                    ? 'SCRIPTED DEMO'
                    : result.execution_mode === 'gemini'
                      ? 'LIVE AI — GEMINI'
                      : result.execution_mode}
                </span>
              </div>

              <div className="run-metadata">
                <span>
                  Run ID: {result.investigation_id}
                </span>

                <span>
                  Saved:{' '}
                  {new Date(
                    result.created_at,
                  ).toISOString()}
                </span>
              </div>

              <p
                className="result-status"
                role="status"
              >
                {statusLabels[result.status] ??
                  result.status}
              </p>

              <h4>
                Detection findings (
                {result.findings.length})
              </h4>

              {result.findings.length === 0 && (
                <p className="muted">
                  No configured detection rule
                  matched this case. This does not
                  establish that all activity is safe.
                </p>
              )}

              {result.findings.map(
                (finding, index) => (
                  <article
                    className="finding-card"
                    key={`${finding.rule_id}-${index}`}
                  >
                    <div className="finding-meta">
                      <span>
                        {finding.rule_id}
                      </span>

                      <span className="severity-label">
                        {finding.severity.toUpperCase()}
                      </span>
                    </div>

                    <h4>{finding.title}</h4>

                    <p>{finding.reason}</p>

                    <p className="evidence-reference">
                      Evidence:{' '}
                      {finding.evidence_ids.join(', ')}
                    </p>
                  </article>
                ),
              )}

              <h4>
                Investigation steps (
                {result.trace.length})
              </h4>

              {result.trace.length === 0 && (
                <p className="muted">
                  No follow-up lookups were performed.
                </p>
              )}

              <ol className="trace-list">
                {result.trace.map(
                  (step, index) => (
                    <li
                      key={`${step.tool}-${index}`}
                    >
                      <code>{step.tool}</code>

                      <p className="trace-query">
                        {step.query}
                      </p>

                      <p>{step.reason}</p>

                      <p className="evidence-reference">
                        {step.result_count} events:{' '}
                        {step.event_ids.length
                          ? step.event_ids.join(', ')
                          : 'None'}
                      </p>
                    </li>
                  ),
                )}
              </ol>

              {result.finish_reason && (
                <div className="finish-note">
                  <h4>Completion note</h4>
                  <p>{result.finish_reason}</p>
                </div>
              )}

              {result.status === 'agent_error' && (
                <div
                  className="error-panel"
                  role="alert"
                >
                  <h4>
                    Investigation stopped safely
                  </h4>

                  <p>
                    {result.error?.message ??
                      'The AI could not complete this investigation.'}
                  </p>

                  {result.error?.step && (
                    <p>
                      Failed at investigation step:{' '}
                      {result.error.step}
                    </p>
                  )}

                  <p>
                    Previous findings and
                    investigation steps were preserved.
                    Human review is required.
                  </p>
                </div>
              )}

              {result.status === 'step_limit' && (
                <p className="muted">
                  The investigation stopped at
                  its configured step limit.
                  Evidence collection may be incomplete.
                </p>
              )}
            </section>
            {result.report && (
              <IncidentReport report={result.report} />
            )}
            {result.investigation_id && result.report && (
            <AINarrative
            key={result.investigation_id}
            investigationId={result.investigation_id}
            />
            )}
            {result.investigation_id && (
              <AnalystReview
                key={result.investigation_id}
                investigationId={result.investigation_id}
              />
            )}
            </>
          )}

          <h3 className="timeline-heading">
            Source timeline
          </h3>

          <p className="muted">
            {caseData.events.length} events ·
            Timestamps shown in UTC
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
                {caseData.events.map(
                  (event) => (
                    <tr key={event.id}>
                      <td className="event-id">
                        {event.id}
                      </td>

                      <td>
                        {new Date(
                          event.timestamp,
                        ).toISOString()}
                      </td>

                      <td>{event.action}</td>
                      <td>{event.outcome}</td>
                      <td>{event.user}</td>
                    </tr>
                  ),
                )}
              </tbody>
            </table>
          </div>

          <details className="raw-evidence">
            <summary>
              Inspect complete source events
            </summary>

            <pre>
              {JSON.stringify(
                caseData.events,
                null,
                2,
              )}
            </pre>
          </details>
        </>
      )}
    </section>
  )
}
