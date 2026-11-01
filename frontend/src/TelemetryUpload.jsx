
import { useState } from 'react'
import './TelemetryUpload.css'

const MAX_BYTES = 5 * 1024 * 1024

export default function TelemetryUpload({ onImported }) {
  const [file, setFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(null)

  async function upload(event) {
    event.preventDefault()
    const form = event.currentTarget
    if (!file || uploading) return

    setError('')
    setSuccess(null)
    setUploading(true)

    try {
      if (file.size > MAX_BYTES) {
        throw new Error('Maximum file size is 5 MB')
      }

      if (!/\.(json|jsonl)$/i.test(file.name)) {
        throw new Error('Choose a JSON or JSONL file')
      }

      const content = await file.text()

      const response = await fetch('/api/imports', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          filename: file.name,
          content,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(
          typeof data.detail === 'string'
            ? data.detail
            : 'Telemetry import failed',
        )
      }

      setSuccess(data)
      setFile(null)
      form.reset()
      onImported?.(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setUploading(false)
    }
  }

  return (
    <section className="telemetry-upload">
      <div>
        <p className="upload-eyebrow">
          SECURITY TELEMETRY INGESTION
        </p>

        <h2>Import Sysmon events</h2>

        <p className="upload-description">
          Upload a JSON or JSONL Sysmon export.
          Supported Event IDs: 1, 3 and 11.
          Maximum size: 5 MB.
        </p>
      </div>

      <form onSubmit={upload} className="upload-form">
        <input
          type="file"
          accept=".json,.jsonl"
          disabled={uploading}
          onChange={(event) => {
            setFile(event.target.files?.[0] ?? null)
            setError('')
            setSuccess(null)
          }}
          aria-label="Select Sysmon telemetry file"
        />

        <button
          type="submit"
          disabled={!file || uploading}
        >
          {uploading ? 'Importing...' : 'Import telemetry'}
        </button>
      </form>

      {file && (
        <p className="upload-selected">
          Selected: {file.name}
        </p>
      )}

      {error && (
        <p className="upload-error" role="alert">
          {error}
        </p>
      )}

      {success && (
        <p className="upload-success" role="status">
          Imported {success.event_count} events
          into case {success.case_id}.
        </p>
      )}

      <p className="upload-note">
        Import does not execute log content.
        Only upload sanitized or synthetic telemetry.
        Imported Sysmon cases require endpoint detection
        rules, which we'll add in the next upgrade.
      </p>
    </section>
  )
}