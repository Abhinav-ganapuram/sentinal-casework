
import { useEffect, useState } from 'react'
import './AnalystReview.css'

const VERDICTS = [
  { value: 'suspicious', label: 'Suspicious activity' },
  { value: 'benign', label: 'Benign activity' },
  { value: 'needs_more_evidence', label: 'Needs more evidence' },
]

const verdictLabel = (value) =>
  VERDICTS.find((item) => item.value === value)?.label ?? value

export default function AnalystReview({ investigationId }) {
  const [reviews, setReviews] = useState([])
  const [verdict, setVerdict] = useState('needs_more_evidence')
  const [notes, setNotes] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  useEffect(() => {
    const controller = new AbortController()

    async function loadReviews() {
      setLoading(true)
      setReviews([])
      setError('')
      setSuccess('')
      setVerdict('needs_more_evidence')
      setNotes('')

      try {
        const response = await fetch(
          `/api/investigations/${encodeURIComponent(investigationId)}/reviews`,
          { signal: controller.signal },
        )

        if (!response.ok) {
          throw new Error('Could not load analyst reviews')
        }

        const data = await response.json()

        if (!controller.signal.aborted) {
          setReviews(data)
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

    loadReviews()

    return () => controller.abort()
  }, [investigationId])

  async function submitReview(event) {
    event.preventDefault()

    if (saving || loading || !notes.trim()) return

    setSaving(true)
    setError('')
    setSuccess('')

    try {
      const response = await fetch(
        `/api/investigations/${encodeURIComponent(investigationId)}/reviews`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            verdict,
            notes: notes.trim(),
          }),
        },
      )

      if (!response.ok) {
        const problem = await response.json().catch(() => ({}))
        const message =
          typeof problem.detail === 'string'
            ? problem.detail
            : 'Could not save analyst review'

        throw new Error(message)
      }

      const savedReview = await response.json()

      setReviews((previous) => [...previous, savedReview])
      setNotes('')
      setSuccess('Analyst review saved successfully.')
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <section className="analyst-review">
      <div className="review-heading">
        <div>
          <p className="review-eyebrow">
            HUMAN-IN-THE-LOOP
          </p>
          <h3>Analyst review</h3>
          <p>
            Record a human assessment without modifying
            the original investigation.
          </p>
        </div>
      </div>

      <form onSubmit={submitReview} className="review-form">
        <label htmlFor="review-verdict">
          Analyst verdict
        </label>

        <select
          id="review-verdict"
          value={verdict}
          onChange={(event) => setVerdict(event.target.value)}
          disabled={saving || loading}
        >
          {VERDICTS.map((item) => (
            <option key={item.value} value={item.value}>
              {item.label}
            </option>
          ))}
        </select>

        <label htmlFor="review-notes">
          Investigation notes
        </label>

        <textarea
          id="review-notes"
          value={notes}
          onChange={(event) => setNotes(event.target.value)}
          maxLength={2000}
          rows={5}
          placeholder="Explain your verdict using the available evidence..."
          disabled={saving || loading}
          required
        />

        <div className="review-form-footer">
          <span>{notes.length}/2000 characters</span>

          <button
            type="submit"
            disabled={saving || loading || !notes.trim()}
          >
            {saving ? 'Saving review...' : 'Submit analyst review'}
          </button>
        </div>
      </form>

      {error && (
        <p className="review-error" role="alert">
          {error}
        </p>
      )}

      {success && (
        <p className="review-success" role="status">
          {success}
        </p>
      )}

      <div className="review-history">
        <h4>Review history ({reviews.length})</h4>

        {loading ? (
          <p>Loading reviews...</p>
        ) : reviews.length === 0 ? (
          <p className="review-muted">
            No analyst reviews have been submitted yet.
          </p>
        ) : (
          <div className="review-history-list">
            {reviews.map((review) => (
              <article
                key={review.review_id}
                className="review-entry"
              >
                <div className="review-entry-header">
                  <span className={`review-verdict ${review.verdict}`}>
                    {verdictLabel(review.verdict)}
                  </span>

                  <time dateTime={review.created_at}>
                    {new Date(review.created_at).toLocaleString()}
                  </time>
                </div>

                <p>{review.notes}</p>
              </article>
            ))}
          </div>
        )}
      </div>
    </section>
  )
}