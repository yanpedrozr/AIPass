import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { SeverityBadge } from "../components/Badges.jsx";
import ConfirmDialog from "../components/ConfirmDialog.jsx";
import CopyButton from "../components/CopyButton.jsx";
import CredentialForm from "../components/CredentialForm.jsx";
import ScoreRing from "../components/ScoreRing.jsx";
import { useToast } from "../context/ToastContext.jsx";
import useVault from "../hooks/useVault.js";
import { deleteCredential } from "../services/api.js";
import { SEVERITIES, SEVERITY_CLASS } from "../utils/labels.js";

function SecuritySummary({ report, loading, error }) {
  if (error && !report) {
    return <p className="notice notice-warning">Não foi possível analisar o cofre: {error}</p>;
  }
  if (!report) {
    return (
      <div className="card summary-card">
        <span className="spinner" aria-hidden="true" /> Analisando a segurança do cofre...
      </div>
    );
  }
  const { summary } = report;
  return (
    <div className={`card summary-card ${loading ? "is-loading" : ""}`}>
      <ScoreRing score={summary.score} size="small" />
      <div className="summary-text">
        <strong>
          {summary.at_risk === 0
            ? "Nenhuma credencial em risco"
            : `${summary.at_risk} de ${summary.credentials} credencial(is) em risco`}
        </strong>
        <div className="chips">
          {SEVERITIES.filter((s) => summary.alerts_by_severity[s]).map((s) => (
            <span key={s} className={`chip chip-${SEVERITY_CLASS[s]}`}>
              {summary.alerts_by_severity[s]} {s}
            </span>
          ))}
          {loading && <span className="muted small">atualizando...</span>}
        </div>
      </div>
      <Link to="/seguranca" className="btn btn-secondary btn-small">
        Ver alertas e recomendações
      </Link>
    </div>
  );
}

function CredentialRow({ credential, severity, onEdit, onDelete }) {
  const [visible, setVisible] = useState(false);
  return (
    <li className="credential">
      <div className="credential-avatar" aria-hidden="true">
        {credential.service.charAt(0).toUpperCase()}
      </div>
      <div className="credential-main">
        <div className="credential-title">
          <strong>{credential.service}</strong>
          <SeverityBadge severity={severity} />
        </div>
        {credential.username && <div className="muted small">{credential.username}</div>}
        <div className="credential-password mono">
          {visible ? credential.password : "•".repeat(Math.min(credential.password.length, 16))}
        </div>
      </div>
      <div className="credential-actions">
        <button type="button" className="btn btn-ghost btn-small" onClick={() => setVisible((v) => !v)}>
          {visible ? "Ocultar" : "Mostrar"}
        </button>
        {credential.username && (
          <CopyButton text={credential.username} label="Copiar usuário" message="Usuário copiado." />
        )}
        <CopyButton text={credential.password} label="Copiar senha" message="Senha copiada." sensitive />
        <button type="button" className="btn btn-ghost btn-small" onClick={onEdit}>
          Editar
        </button>
        <button type="button" className="btn btn-ghost btn-small text-danger" onClick={onDelete}>
          Excluir
        </button>
      </div>
    </li>
  );
}

export default function Vault() {
  const { credentials, error, report, reportError, reportLoading, refresh } = useVault();
  const [search, setSearch] = useState("");
  const [editing, setEditing] = useState(null); // null, "new" ou a credencial
  const [deleting, setDeleting] = useState(null);
  const [busy, setBusy] = useState(false);
  const showToast = useToast();

  const severityById = useMemo(
    () => Object.fromEntries((report?.credentials ?? []).map((c) => [c.id, c.severity])),
    [report]
  );

  const filtered = useMemo(() => {
    const term = search.trim().toLocaleLowerCase("pt-BR");
    if (!credentials) return [];
    return credentials.filter(
      (c) =>
        !term ||
        c.service.toLocaleLowerCase("pt-BR").includes(term) ||
        c.username.toLocaleLowerCase("pt-BR").includes(term)
    );
  }, [credentials, search]);

  async function confirmDelete() {
    setBusy(true);
    try {
      await deleteCredential(deleting.id);
      showToast(`${deleting.service} foi excluído do cofre.`);
      setDeleting(null);
      refresh();
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <div className="page-header">
        <div>
          <h1>Cofre</h1>
          <p className="muted">
            Senhas cifradas com AES-256-GCM. A chave do cofre existe só enquanto você está logado.
          </p>
        </div>
        <button type="button" className="btn btn-primary vault-add-button" onClick={() => setEditing("new")}>
          Adicionar
        </button>
      </div>

      {credentials?.length > 0 && (
        <SecuritySummary report={report} loading={reportLoading} error={reportError} />
      )}

      {error && <p className="notice notice-error">{error}</p>}

      {credentials === null && !error && (
        <p className="muted">
          <span className="spinner" aria-hidden="true" /> Abrindo o cofre...
        </p>
      )}

      {credentials?.length === 0 && (
        <div className="card empty-state">
          <h2>Seu cofre está vazio</h2>
          <p className="muted">
            Adicione a primeira credencial. Cada senha salva é analisada na hora: força, vazamentos e
            reutilização entre serviços.
          </p>
          <button type="button" className="btn btn-primary" onClick={() => setEditing("new")}>
            Adicionar credencial
          </button>
        </div>
      )}

      {credentials?.length > 0 && (
        <>
          <input
            type="search"
            className="search"
            placeholder="Buscar por serviço ou usuário"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Buscar credenciais"
          />
          {filtered.length === 0 ? (
            <p className="muted">Nenhuma credencial encontrada para “{search}”.</p>
          ) : (
            <ul className="credential-list">
              {filtered.map((credential) => (
                <CredentialRow
                  key={credential.id}
                  credential={credential}
                  severity={severityById[credential.id]}
                  onEdit={() => setEditing(credential)}
                  onDelete={() => setDeleting(credential)}
                />
              ))}
            </ul>
          )}
        </>
      )}

      {editing && (
        <CredentialForm
          credential={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={refresh}
        />
      )}

      {deleting && (
        <ConfirmDialog
          title="Excluir credencial"
          message={`Excluir ${deleting.service}${deleting.username ? ` (${deleting.username})` : ""} do cofre? Esta ação não pode ser desfeita.`}
          confirmLabel="Excluir"
          busy={busy}
          onConfirm={confirmDelete}
          onCancel={() => setDeleting(null)}
        />
      )}
    </section>
  );
}
