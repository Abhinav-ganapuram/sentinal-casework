import { useEffect, useState } from 'react'

export default function CaseDetail({ caseId, onClose }) {
  const [caseData, setCaseData] = useState(null)
  const [error, setError] = useState('')

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
    return () => controller.abort()
  }, [caseId])

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
                    <td>
                      {new Date(event.timestamp).toISOString()}
                    </td>
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