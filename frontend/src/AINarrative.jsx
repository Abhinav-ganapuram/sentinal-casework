
import { useEffect, useState } from 'react'
import './AINarrative.css'

export default function AINarrative({ investigationId }) {
  const [narrative, setNarrative] = useState(null)
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()

    setNarrative(null)
    setLoading(true)
    setError('')

    async function loadNarrative() {
      try {
        const response = await fetch(
          `/api/investigations/${encodeURIComponent(investigationId)}/narrative`,
          { signal: controller.signal },
        )

        if (response.status === 404) return

        if (!response.ok) {
          throw new Error('Could not load saved AI narrative')
        }

        const data = await response.json()

        if (!controller.signal.aborted) {
          setNarrative(data.narrative)
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

    loadNarrative()
    return () => controller.abort()
  }, [investigationId])

  async function generateNarrative() {
    if (generating) return

    setGenerating(true)
    setError('')

    try {
      const response = await fetch(
        `/api/investigations/${encodeURIComponent(investigationId)}/narrative`,
        { method: 'POST' },
      )

      if (!response.ok) {
        const problem = await response.json().catch(() => ({}))

        throw new Error(
          typeof problem.detail === 'string'
            ? problem.detail
            : 'AI narrative generation failed',
        )
      }

      const data = await response.json()
      setNarrative(data.narrative)
    } catch (err) {
      setError(err.message)
    } finally {
      setGenerating(false)
    }
  }

  return (
    <section className="ai-narrative">
      <div className="ai-narrative-header">
        <div>
          <p className="ai-narrative-eyebrow">
            GEMINI · EVIDENCE-GROUNDED ANALYSIS
          </p>
          <h3>AI Incident Narrative</h3>
          <p className="ai-narrative-muted">
            AI-generated draft · Requires analyst verification
          </p>
        </div>

        {!narrative && !loading && (
          <button
            onClick={generateNarrative}
            disabled={generating}
            className="ai-narrative-button"
          >
            {generating
              ? 'Generating narrative...'
              : 'Generate AI Narrative'}
          </button>
        )}
      </div>

      {loading && <p>Loading saved narrative...</p>}

      {generating && (
        <p role="status">
          Gemini is analyzing the verified evidence.
          This may take some time.
        </p>
      )}

      {error && (
        <p className="ai-narrative-error" role="alert">
          {error}
        </p>
      )}

      {narrative && (
        <div className="ai-narrative-content">
          <div className="ai-narrative-section">
            <h4>Executive summary</h4>
            <p>{narrative.executive_summary}</p>
          </div>

          <div className="ai-narrative-section">
            <h4>Key observations</h4>
            {narrative.observations.map((item, index) => (
              <article className="ai-observation" key={index}>
                <p>{item.statement}</p>
                <div className="ai-evidence-ids">
                  {item.event_ids.map((id) => (
                    <code key={id}>{id}</code>
                  ))}
                </div>
              </article>
            ))}
          </div>

          <div className="ai-narrative-section">
            <h4>Potential security implications</h4>
            <ul>
              {narrative.implications.map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ul>
          </div>

          <div className="ai-narrative-section">
            <h4>Uncertainty and missing evidence</h4>
            <ul>
              {narrative.uncertainties.map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ul>
          </div>

          <div className="ai-narrative-section">
            <h4>Recommended next steps</h4>
            <ol>
              {narrative.next_steps.map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ol>
          </div>

          <p className="ai-narrative-disclaimer">
            Evidence references are checked against the
            investigation report. Their existence does not
            automatically verify every AI-generated claim.
            Analyst review remains required.
          </p>
        </div>
      )}
    </section>
  )
}
