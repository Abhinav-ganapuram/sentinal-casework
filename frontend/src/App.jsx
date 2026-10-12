import { useEffect, useState } from 'react'
import CaseDetail from './CaseDetail'
import './App.css'

export default function App() {
  const [cases, setCases] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [attempt, setAttempt] = useState(0)
  const [selectedCase, setSelectedCase] = useState(null)

  useEffect(() => {
    const controller = new AbortController()

    async function loadCases() {
      try {
        const response = await fetch('/api/cases', {
          signal: controller.signal,
        })

        if (!response.ok) {
          throw new Error(`Request failed (${response.status})`)
        }

        const data = await response.json()

        if (!Array.isArray(data)) {
          throw new Error('Unexpected case list format')
        }

        if (!controller.signal.aborted) {
          setCases(data)
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

    loadCases()
    return () => controller.abort()
  }, [attempt])

  function retry() {
    setError('')
    setLoading(true)
    setAttempt((value) => value + 1)
  }

  const eventCount = cases.reduce(
    (total, item) => total + item.event_count,
    0,
  )

  return (
    <main className="workspace">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">S</span>
          <span>
            Sentinel<span className="muted"> / Casework</span>
          </span>
        </div>
        <span className="badge">SYNTHETIC DATA · DEMO</span>
      </header>

      <section className="intro">
        <p className="eyebrow">SECURITY OPERATIONS WORKSPACE</p>
        <h1>
          Every investigation starts
          <br />
          with the evidence.
        </h1>
        <p className="subtitle">
          Explore synthetic incidents, trace investigation steps,
          and review the evidence behind each finding.
        </p>
      </section>

      <section className="metrics" aria-label="Case statistics">
        <div className="metric">
          <span>Available cases</span>
          <strong>{loading || error ? '—' : cases.length}</strong>
        </div>

        <div className="metric">
          <span>Source events</span>
          <strong>{loading || error ? '—' : eventCount}</strong>
        </div>

        <div className="metric">
          <span>Investigation mode</span>
          <strong className="mode-label">Scripted demo</strong>
        </div>
      </section>

      <section className="case-section">
        <div className="section-heading">
          <h2>Case library</h2>
          <span className="muted">
            Synthetic investigation scenarios
          </span>
        </div>

        {loading && <p role="status">Loading cases…</p>}

        {!loading && error && (
          <div className="error-panel" role="alert">
            <p>Could not load cases: {error}</p>
            <p>Check that the backend is running on port 8000.</p>
            <button onClick={retry}>Try again</button>
          </div>
        )}

        {!loading && !error && cases.length === 0 && (
          <p>No cases available.</p>
        )}

        {!loading && !error && (
          <div className="case-grid">
            {cases.map((item) => (
              <article className="case-card" key={item.case_id}>
                <span className="case-id">{item.case_id}</span>
                <h3>{item.title}</h3>

                <div className="case-footer">
                  <span>{item.event_count} source events</span>
                  <span>Synthetic fixture</span>
                </div>

                <button
                  className="open-case-button"
                  onClick={() => setSelectedCase(item.case_id)}
                  aria-label={`Open ${item.case_id}`}
                  aria-pressed={selectedCase === item.case_id}
                >
                  {selectedCase === item.case_id
                    ? 'Case selected'
                    : 'Open case →'}
                </button>
              </article>
            ))}
          </div>
        )}
      </section>

      {selectedCase && (
        <CaseDetail
          key={selectedCase}
          caseId={selectedCase}
          onClose={() => setSelectedCase(null)}
        />
      )}
    </main>
  )
}