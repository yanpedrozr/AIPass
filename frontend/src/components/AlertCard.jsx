import { SeverityBadge } from "./Badges.jsx";
import { ALERT_TYPE_LABELS, SEVERITY_CLASS } from "../utils/labels.js";

// Um alerta do backend: gravidade, mensagem e recomendação. `onEdit` recebe o
// id da credencial para abrir a edição direto do alerta.
export default function AlertCard({ alert, onEdit }) {
  return (
    <article className={`alert-card border-${SEVERITY_CLASS[alert.severity]}`}>
      <header className="alert-card-header">
        <SeverityBadge severity={alert.severity} />
        <span className="alert-type">{ALERT_TYPE_LABELS[alert.type] ?? alert.type}</span>
      </header>
      <p className="alert-message">{alert.message}</p>
      <p className="alert-recommendation">
        <strong>Recomendação:</strong> {alert.recommendation}
      </p>
      {onEdit && (
        <div className="alert-actions">
          {alert.credential_ids.map((id, i) => (
            <button key={id} type="button" className="btn btn-secondary btn-small" onClick={() => onEdit(id)}>
              Trocar senha de {alert.services[i]}
            </button>
          ))}
        </div>
      )}
    </article>
  );
}

// Aviso quando algum analisador não rodou (ex.: HIBP fora do ar).
export function ChecksNotice({ checks }) {
  if (!checks) return null;
  const missing = [];
  if (!checks.breach) missing.push("a verificação de vazamentos (Have I Been Pwned indisponível)");
  if (!checks.strength) missing.push("a análise de força (modelo não treinado)");
  if (!checks.similarity) missing.push("a similaridade com vazamentos (base indisponível)");
  if (!missing.length) return null;
  return (
    <p className="notice notice-warning">
      Análise incompleta: não foi possível executar {missing.join(", ")}. Tente novamente mais tarde.
    </p>
  );
}
