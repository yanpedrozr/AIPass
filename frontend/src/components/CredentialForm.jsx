import { useState } from "react";
import AlertCard, { ChecksNotice } from "./AlertCard.jsx";
import Modal from "./Modal.jsx";
import PasswordInput from "./PasswordInput.jsx";
import StrengthMeter from "./StrengthMeter.jsx";
import { useToast } from "../context/ToastContext.jsx";
import { createCredential, generatePassword, updateCredential } from "../services/api.js";

const GENERATED_LENGTH = 20;

// Formulário de criar/editar credencial em um modal. Depois de salvar, mostra
// os alertas que o backend devolve para a senha (alertas em tempo real).
export default function CredentialForm({ credential, onClose, onSaved }) {
  const [editingId, setEditingId] = useState(credential?.id ?? null);
  const [service, setService] = useState(credential?.service ?? "");
  const [username, setUsername] = useState(credential?.username ?? "");
  const [password, setPassword] = useState(credential?.password ?? "");
  const [saving, setSaving] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState(null);
  const [review, setReview] = useState(null);
  const showToast = useToast();

  async function handleGenerate() {
    setGenerating(true);
    setError(null);
    try {
      const data = await generatePassword({ length: GENERATED_LENGTH });
      setPassword(data.password);
    } catch (err) {
      setError(err.message);
    } finally {
      setGenerating(false);
    }
  }

  async function handleSubmit(event) {
    event.preventDefault();
    if (!service.trim() || !password) {
      setError("Preencha o serviço e a senha.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const fields = { service: service.trim(), username, password };
      const data = editingId
        ? await updateCredential(editingId, fields)
        : await createCredential(fields);
      onSaved(data.credential);
      if (data.alerts.length || !Object.values(data.checks).every(Boolean)) {
        setEditingId(data.credential.id);
        setReview(data);
      } else {
        showToast("Credencial salva. Nenhum problema de segurança encontrado.");
        onClose();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  function changePasswordNow() {
    setReview(null);
    setPassword("");
  }

  if (review) {
    return (
      <Modal title="Credencial salva" onClose={onClose}>
        <p>
          <strong>{review.credential.service}</strong> foi salvo no cofre.
          {review.alerts.length > 0 &&
            ` Encontramos ${review.alerts.length} problema(s) de segurança nesta senha:`}
        </p>
        <ChecksNotice checks={review.checks} />
        <div className="alert-list">
          {review.alerts.map((alert, i) => (
            <AlertCard key={i} alert={alert} />
          ))}
        </div>
        <div className="form-actions">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Fechar
          </button>
          {review.alerts.length > 0 && (
            <button type="button" className="btn btn-primary" onClick={changePasswordNow}>
              Trocar a senha agora
            </button>
          )}
        </div>
      </Modal>
    );
  }

  return (
    <Modal title={editingId ? "Editar credencial" : "Nova credencial"} onClose={onClose}>
      <form onSubmit={handleSubmit} className="form">
        <label htmlFor="cred-service">Serviço</label>
        <input
          id="cred-service"
          value={service}
          onChange={(e) => setService(e.target.value)}
          maxLength={128}
          placeholder="Ex.: Gmail"
          autoComplete="off"
          required
        />

        <label htmlFor="cred-username">Usuário ou e-mail (opcional)</label>
        <input
          id="cred-username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          maxLength={256}
          placeholder="Ex.: alice@gmail.com"
          autoComplete="off"
        />

        <div className="label-row">
          <label htmlFor="cred-password">Senha</label>
          <button type="button" className="link-button" onClick={handleGenerate} disabled={generating}>
            {generating ? "Gerando..." : `Gerar senha forte (${GENERATED_LENGTH} caracteres)`}
          </button>
        </div>
        <PasswordInput
          id="cred-password"
          value={password}
          onChange={setPassword}
          maxLength={4096}
          autoComplete="new-password"
          required
        />
        <StrengthMeter password={password} />

        {error && <p className="notice notice-error">{error}</p>}

        <div className="form-actions">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Cancelar
          </button>
          <button type="submit" className="btn btn-primary" disabled={saving}>
            {saving ? "Salvando e analisando..." : "Salvar"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
