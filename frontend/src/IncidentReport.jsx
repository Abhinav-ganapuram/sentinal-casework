
import './IncidentReport.css'

export default function IncidentReport({ report }) {
  if (!report) {
    return (
      <p className="muted">
        No incident report is available for this investigation.
      </p>
    )
  }

  function exportReport() {
    const content = JSON.stringify(report, null, 2)

    const blob = new Blob([content], {
      type: 'application/json',
    })

    const url = URL.createObjectURL(blob)

    const link = document.createElement('a')
    link.href = url
    link.download = `${report.case_id}-incident-report.json`

    document.body.appendChild(link)
    link.click()
    link.remove()

    URL.revokeObjectURL(url)
  }

  return (
    <section className="incident-report">
      <div className="report-header">
        <div>
          <p className="report-eyebrow">
            SENTINEL CASEWORK · INCIDENT REPORT
          </p>

          <h3>{report.title}</h3>
        </div>

        <button
          className="report-export"
          onClick={exportReport}
        >
          Export JSON
        </button>
      </div>

      <div className="report-summary-grid">
        <div className="report-stat">
          <span>Severity</span>
          <strong>{report.severity?.toUpperCase()}</strong>
        </div>

        <div className="report-stat">
          <span>Findings</span>
          <strong>{report.finding_count}</strong>
        </div>

        <div className="report-stat">
          <span>Investigation steps</span>
          <strong>{report.investigation_step_count}</strong>
        </div>

        <div className="report-stat">
          <span>Status</span>
          <strong>{report.status?.replaceAll('_', ' ')}</strong>
        </div>
      </div>

      <div className="report-section">
        <h4>Investigation summary</h4>
        <p>{report.summary}</p>
      </div>

      <div className="report-section">
        <h4>Evidence timeline</h4>

        {report.timeline?.length ? (
          <div className="report-timeline">
            {report.timeline.map((event) => (
              <article
                className="report-event"
                key={event.event_id}
              >
                <div className="report-event-heading">
                  <strong>{event.event_id}</strong>
                  <time dateTime={event.timestamp}>
                    {new Date(event.timestamp).toLocaleString()}
                  </time>
                </div>

                <p>
                  <strong>{event.action}</strong>
                  {' · '}
                  {event.outcome}
                </p>

                <p className="muted">
                  User: {event.user}
                </p>

                {event.source_ip && (
                  <p className="muted">
                    Source IP: {event.source_ip}
                  </p>
                )}
              </article>
            ))}
          </div>
        ) : (
          <p className="muted">
            No events were referenced by the investigation.
          </p>
        )}
      </div>

      <div className="report-section">
        <h4>Recommended analyst actions</h4>

        {report.recommendations?.length ? (
          <ol>
            {report.recommendations.map((action, index) => (
              <li key={index}>{action}</li>
            ))}
          </ol>
        ) : (
          <p className="muted">
            No response actions recommended.
          </p>
        )}
      </div>

      <div className="report-section">
        <h4>Limitations and uncertainty</h4>

        <ul>
          {report.limitations?.map((limitation, index) => (
            <li key={index}>{limitation}</li>
          ))}
        </ul>
      </div>

      <div className="report-footer">
        <span>
          Generated using verified case evidence
        </span>
        <strong>Human review required</strong>
      </div>
    </section>
  )
}