
import { useEffect, useState } from 'react'
import './PerformanceDashboard.css'

function formatTime(ms) {
  if (ms == null) return '—'
  if (ms < 1000) return `${Math.round(ms)} ms`
  return `${(ms / 1000).toFixed(2)} s`
}

export default function PerformanceDashboard() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [refresh, setRefresh] = useState(0)

  useEffect(() => {
    const controller = new AbortController()

    async function load() {
      setLoading(true)
      setError('')

      try {
        const response = await fetch(
          '/api/metrics/investigations',
          { signal: controller.signal },
        )

        if (!response.ok) {
          throw new Error(`Metrics API returned ${response.status}`)
        }

        const payload = await response.json()

        if (!controller.signal.aborted) {
          setData(payload)
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

    load()
    return () => controller.abort()
  }, [refresh])

  const summary = data?.overall
  const recent = data?.recent_investigations ?? []

  return (
    <section className="performance-panel">
      <div className="performance-heading">
        <div>
          <p className="performance-eyebrow">
            INVESTIGATION ANALYTICS
          </p>
          <h2>Performance overview</h2>
          <p>
            Measurements from saved investigation runs.
          </p>
        </div>

        <button
          onClick={() => setRefresh((value) => value + 1)}
          disabled={loading}
        >
          Refresh metrics
        </button>
      </div>

      {loading && <p role="status">Loading metrics...</p>}

      {error && (
        <p role="alert" className="performance-error">
          {error}
        </p>
      )}

      {!loading && !error && data && (
        <>
          <div className="performance-stats">
            <div>
              <span>Measured runs</span>
              <strong>{summary.run_count}</strong>
            </div>

            <div>
              <span>Average duration</span>
              <strong>
                {formatTime(summary.average_duration_ms)}
              </strong>
            </div>

            <div>
              <span>P95 duration</span>
              <strong>
                {formatTime(summary.p95_duration_ms)}
              </strong>
            </div>

            <div>
              <span>Avg. AI decisions</span>
              <strong>
                {summary.average_decision_count ?? '—'}
              </strong>
            </div>
          </div>

          <h3>Execution mode comparison</h3>

          <div className="performance-modes">
            {Object.entries(data.by_mode).length === 0 ? (
              <p>No measured investigations yet.</p>
            ) : (
              Object.entries(data.by_mode).map(([mode, stats]) => (
                <div key={mode} className="performance-mode">
                  <strong>{mode.toUpperCase()}</strong>
                  <span>{stats.run_count} runs</span>
                  <span>
                    Average: {formatTime(stats.average_duration_ms)}
                  </span>
                  <span>
                    Decisions: {stats.average_decision_count}
                  </span>
                </div>
              ))
            )}
          </div>

          <h3>Recent measured investigations</h3>

          {recent.length === 0 ? (
            <p>
              Run a new Demo investigation to start collecting
              metrics. Older runs do not contain timing data.
            </p>
          ) : (
            <div className="performance-table-scroll">
              <table className="performance-table">
                <thead>
                  <tr>
                    <th>Case</th>
                    <th>Mode</th>
                    <th>Status</th>
                    <th>Total</th>
                    <th>Decision time</th>
                    <th>Calls</th>
                    <th>Lookups</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map((run) => (
                    <tr key={run.investigation_id}>
                      <td>{run.case_id}</td>
                      <td>{run.mode}</td>
                      <td>{run.status}</td>
                      <td>{formatTime(run.total_duration_ms)}</td>
                      <td>
                        {formatTime(run.decision_duration_ms)}
                      </td>
                      <td>{run.decision_count}</td>
                      <td>{run.tool_lookup_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <p className="performance-footnote">
            Metrics use the most recent 500 recorded investigation
            results with timing data. P95 is computed using the
            nearest-rank method. Results from very small samples
            should not be treated as representative benchmarks.
          </p>
        </>
      )}
    </section>
  )
}