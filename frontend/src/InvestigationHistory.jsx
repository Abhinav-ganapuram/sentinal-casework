import { useEffect, useState } from 'react'

export default function InvestigationHistory({
  caseId,
  onOpen,
  disabled,
  selectedId,
}) {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()

    async function loadHistory() {
      try {
        const response = await fetch(
          `/api/cases/${encodeURIComponent(caseId)}/investigations`,
          { signal: controller.signal },
        )

        if (!response.ok) {
          throw new Error(`Could not load history (${response.status})`)
        }

        const data = await response.json()

        if (!controller.signal.aborted) {
          setHistory(data)
        }
      } catch (err) {
        if (!controller.signal.aborted) {
          setError(err.message)
        }
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false)
        }
      }
    }

    loadHistory()
    return () => controller.abort()
  }, [caseId])

  return (
    <section className="history-panel" aria-labelledby="history-heading">
      <h3 id="history-heading">Saved investigations</h3>
      <p className="muted">
        Latest 50 runs · Newest first · Times shown in UTC
      </p>

      {loading && <p role="status">Loading saved runs…</p>}
      {error && <p role="alert">{error}</p>}

      {!loading && !error && history.length === 0 && (
        <p className="muted">
          No saved investigations yet. Run a demo to create one.
        </p>
      )}

      {!loading && !error && (
        <ul className="history-list">
          {history.map((run) => (
            <li key={run.investigation_id}>
              <div className="history-summary">
                <time dateTime={run.created_at}>
                  {new Date(run.created_at).toISOString()}
                </time>
                <span className="muted">
                  {run.execution_mode.toUpperCase()} ·{' '}
                  {run.status.replaceAll('_', ' ')} ·{' '}
                  {run.finding_count} findings
                </span>
                <code>{run.investigation_id}</code>
              </div>

              <button
                className="secondary-button"
                disabled={disabled}
                onClick={() => onOpen(run.investigation_id)}
                aria-pressed={selectedId === run.investigation_id}
              >
                {selectedId === run.investigation_id
                  ? 'Viewing this run'
                  : 'Open saved run'}
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}