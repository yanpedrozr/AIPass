import { RISK_CLASS, SEVERITY_CLASS, STRENGTH_CLASS } from "../utils/labels.js";

export function SeverityBadge({ severity }) {
  if (!severity) return <span className="badge badge-ok">Sem alertas</span>;
  return <span className={`badge badge-${SEVERITY_CLASS[severity]}`}>{severity}</span>;
}

export function StrengthBadge({ strength }) {
  if (!strength) return <span className="badge badge-muted">—</span>;
  return <span className={`badge badge-${STRENGTH_CLASS[strength]}`}>{strength}</span>;
}

export function RiskBadge({ risk }) {
  if (!risk) return <span className="badge badge-muted">—</span>;
  return <span className={`badge badge-${RISK_CLASS[risk]}`}>{risk}</span>;
}
