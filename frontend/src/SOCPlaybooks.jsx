
import './SOCPlaybooks.css'

export default function SOCPlaybooks({ playbooks = [] }) {
  if (!playbooks.length) {
    return null
  }

  return (
    <section
      className="soc-playbooks"
      aria-label="SOC investigation playbooks"
    >
      <header className="soc-playbooks-header">
        <p className="soc-playbooks-eyebrow">
          EVIDENCE-BASED INVESTIGATION GUIDANCE
        </p>

        <h3>SOC investigation playbooks</h3>

        <p>
          Deterministic evidence checks and recommended analyst
          follow-up. No containment actions are executed.
        </p>
      </header>

      {playbooks.map((playbook) => (
        <article
          className="soc-playbook"
          key={`${playbook.playbook_id}-${playbook.finding_index}`}
        >
          <div className="soc-playbook-heading">
            <h4>
              {playbook.playbook_id} · {playbook.name}
            </h4>

            <span
              className={
                playbook.status === 'evidence_checked'
                  ? 'soc-status-complete'
                  : 'soc-status-incomplete'
              }
            >
              {playbook.status === 'evidence_checked'
                ? 'Evidence checked'
                : 'Evidence incomplete'}
            </span>
          </div>

          <p className="soc-playbook-subtitle">
            {playbook.rule_id} · Finding {playbook.finding_index + 1}
            {' · '}
            Investigation:{' '}
            {playbook.investigation_status?.replaceAll('_', ' ')}
          </p>

          <h5>Required evidence</h5>

          <ul className="soc-playbook-checks">
            {playbook.requirements.map((item) => (
              <li key={item.key}>
                <span>{item.label}</span>
                <strong>
                  {item.satisfied ? 'Present' : 'Missing'}
                </strong>
              </li>
            ))}
          </ul>

          <h5>Read-only investigation lookups</h5>

          <ul className="soc-playbook-checks">
            {playbook.lookups.map((lookup) => (
              <li key={lookup.tool}>
                <code>{lookup.tool}</code>
                <strong>
                  {lookup.executed ? 'Executed' : 'Not executed'}
                </strong>
              </li>
            ))}
          </ul>

          <h5>Recommended analyst actions</h5>

          <ol className="soc-playbook-actions">
            {playbook.analyst_actions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ol>

          <h5>Context not independently verified</h5>

          <ul className="soc-playbook-actions">
            {playbook.context_to_verify.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>

          <p className="soc-playbook-caution">
            Human review required · No response actions executed
          </p>
        </article>
      ))}
    </section>
  )
}