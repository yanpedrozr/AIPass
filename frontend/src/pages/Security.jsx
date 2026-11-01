import { useState } from "react";
import { Link } from "react-router-dom";
import AlertCard, { ChecksNotice } from "../components/AlertCard.jsx";
import { RiskBadge, SeverityBadge, StrengthBadge } from "../components/Badges.jsx";
import CredentialForm from "../components/CredentialForm.jsx";
import ScoreRing from "../components/ScoreRing.jsx";
import useVault from "../hooks/useVault.js";
import { SEVERITIES, SEVERITY_CLASS, formatNumber } from "../utils/labels.js";

function BreachCount({ count }) {
  if (count === null) return <span className="muted" title="HIBP indisponível">?</span>;
  if (count === 0) return <span className="text-strong">Nenhum</span>;
  return <strong className="text-weak">{formatNumber(count)}</strong>;
}

export default function Security() {
  const { credentials, report, reportError, reportLoading, refresh, findCredential } = useVault();
  const [filter, setFilter] = useState(null);
  const [editing, setEditing] = useState(null);

  const alerts = report?.alerts.filter((alert) => !filter || alert.severity === filter) ?? [];

  return (
    <section>
      <div className="page-header">
        <div>
          <h1>Segurança do cofre</h1>
          <p className="muted">
            Cada senha passa pela análise de força (Random Forest), pela verificação de vazamentos
            (Have I Been Pwned) e pela similaridade com senhas vazadas. Também procuramos senhas
            repetidas ou parecidas entre os seus serviços.
          </p>
        </div>
        <button type="button" className="btn btn-secondary" onClick={refresh} disabled={reportLoading}>
          {reportLoading ? "Analisando..." : "Reanalisar"}
        </button>
      </div>

      {reportError && <p className="notice notice-error">{reportError}</p>}

      {!report && !reportError && (
        <div className="card empty-state">
          <span className="spinner" aria-hidden="true" />
          <p>Analisando suas senhas. As consultas ao Have I Been Pwned podem levar alguns segundos.</p>
        </div>
      )}

      {report && report.summary.credentials === 0 && (
        <div className="card empty-state">
          <h2>Nada para analisar ainda</h2>
          <p className="muted">Adicione credenciais ao cofre para ver os alertas.</p>
          <Link to="/cofre" className="btn btn-primary">Ir para o cofre</Link>
        </div>
      )}

      {report && report.summary.credentials > 0 && (
        <>
          <div className={`card score-card ${reportLoading ? "is-loading" : ""}`}>
            <ScoreRing score={report.summary.score} />
            <div>
              <h2>
                {report.summary.at_risk === 0
                  ? "Nenhuma credencial em risco"
                  : `${report.summary.at_risk} de ${report.summary.credentials} credencial(is) precisam de atenção`}
              </h2>
              <p className="muted small">
                A nota é a porcentagem de credenciais sem alertas críticos, altos ou médios.
                Última análise: {report.analyzedAt.toLocaleTimeString("pt-BR")}.
              </p>
              <div className="chips" role="group" aria-label="Filtrar por gravidade">
                <button
                  type="button"
                  className={`chip chip-button ${filter === null ? "active" : ""}`}
                  onClick={() => setFilter(null)}
                >
                  Todos ({report.alerts.length})
                </button>
                {SEVERITIES.map((severity) => (
                  <button
                    key={severity}
                    type="button"
                    className={`chip chip-button chip-${SEVERITY_CLASS[severity]} ${filter === severity ? "active" : ""}`}
                    onClick={() => setFilter(severity)}
                    disabled={!report.summary.alerts_by_severity[severity]}
                  >
                    {severity} ({report.summary.alerts_by_severity[severity]})
                  </button>
                ))}
              </div>
            </div>
          </div>

          <ChecksNotice checks={report.checks} />

          <h2 className="section-title">Alertas e recomendações</h2>
          {report.alerts.length === 0 ? (
            <div className="card empty-state">
              <h3>Tudo certo! 🎉</h3>
              <p className="muted">Nenhuma senha fraca, vazada ou reutilizada.</p>
            </div>
          ) : (
            <div className="alert-list">
              {alerts.map((alert, i) => (
                <AlertCard
                  key={`${alert.type}-${alert.credential_ids.join()}-${i}`}
                  alert={alert}
                  onEdit={credentials ? (id) => setEditing(findCredential(id)) : undefined}
                />
              ))}
            </div>
          )}

          <h2 className="section-title">Situação por credencial</h2>
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Serviço</th>
                  <th>Força (IA)</th>
                  <th>Vazamentos</th>
                  <th>Similaridade com vazamentos</th>
                  <th>Gravidade</th>
                </tr>
              </thead>
              <tbody>
                {report.credentials.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <strong>{c.service}</strong>
                      {c.username && <div className="muted small">{c.username}</div>}
                    </td>
                    <td><StrengthBadge strength={c.strength} /></td>
                    <td><BreachCount count={c.pwned_count} /></td>
                    <td><RiskBadge risk={c.leak_similarity} /></td>
                    <td><SeverityBadge severity={c.severity} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {editing && (
        <CredentialForm credential={editing} onClose={() => setEditing(null)} onSaved={refresh} />
      )}
    </section>
  );
}
