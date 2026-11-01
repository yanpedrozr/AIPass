import { useState } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import PasswordInput from "../components/PasswordInput.jsx";
import StrengthMeter from "../components/StrengthMeter.jsx";
import { useAuth } from "../context/AuthContext.jsx";

// Mesmas regras do backend (backend/app/auth/routes.py).
const USERNAME_PATTERN = /^[a-z0-9_.-]{3,32}$/;
const MIN_MASTER_PASSWORD_LENGTH = 12;

function validate(mode, username, password, confirmation) {
  if (mode === "login") return username && password ? null : "Informe o usuário e a senha mestra.";
  if (!USERNAME_PATTERN.test(username)) {
    return "O usuário deve ter de 3 a 32 caracteres: letras minúsculas, números, '_', '.' ou '-'.";
  }
  if (password.length < MIN_MASTER_PASSWORD_LENGTH) {
    return `A senha mestra deve ter pelo menos ${MIN_MASTER_PASSWORD_LENGTH} caracteres.`;
  }
  if (password !== confirmation) return "As senhas mestras não conferem.";
  return null;
}

export default function Auth({ mode }) {
  const { isAuthenticated, login, register, notice } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const isRegister = mode === "register";
  const destination = location.state?.from || "/cofre";

  if (isAuthenticated) return <Navigate to={destination} replace />;

  async function handleSubmit(event) {
    event.preventDefault();
    const normalized = username.trim().toLowerCase();
    const problem = validate(mode, normalized, password, confirmation);
    if (problem) {
      setError(problem);
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      if (isRegister) await register(normalized, password);
      else await login(normalized, password);
      navigate(destination, { replace: true });
    } catch (err) {
      setError(err.message);
      setSubmitting(false);
    }
  }

  return (
    <section className="auth">
      <div className="card auth-card">
        <h1>{isRegister ? "Criar conta" : "Abrir o cofre"}</h1>
        <p className="muted">
          {isRegister
            ? "Escolha uma senha mestra forte. Ela protege todas as outras e não pode ser recuperada."
            : "Entre com seu usuário e sua senha mestra."}
        </p>

        {notice && !isRegister && <p className="notice notice-info">{notice}</p>}

        <form onSubmit={handleSubmit} className="form" noValidate>
          <label htmlFor="auth-username">Usuário</label>
          <input
            id="auth-username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoCapitalize="off"
            spellCheck={false}
            maxLength={32}
            required
          />

          <label htmlFor="auth-password">Senha mestra</label>
          <PasswordInput
            id="auth-password"
            value={password}
            onChange={setPassword}
            autoComplete={isRegister ? "new-password" : "current-password"}
            maxLength={1024}
            required
          />
          {isRegister && (
            <>
              <StrengthMeter password={password} />
              <label htmlFor="auth-confirmation">Confirme a senha mestra</label>
              <PasswordInput
                id="auth-confirmation"
                value={confirmation}
                onChange={setConfirmation}
                autoComplete="new-password"
                maxLength={1024}
                required
              />
              <p className="muted small">
                Mínimo de {MIN_MASTER_PASSWORD_LENGTH} caracteres. Dica: uma frase com várias
                palavras é fácil de lembrar e difícil de adivinhar.
              </p>
            </>
          )}

          {error && <p className="notice notice-error">{error}</p>}

          <button type="submit" className="btn btn-primary btn-block" disabled={submitting}>
            {submitting
              ? isRegister ? "Criando conta..." : "Derivando a chave do cofre..."
              : isRegister ? "Criar conta" : "Entrar"}
          </button>
        </form>

        <p className="auth-switch">
          {isRegister ? (
            <>Já tem conta? <Link to="/entrar">Entrar</Link></>
          ) : (
            <>Ainda não tem conta? <Link to="/cadastro">Criar conta</Link></>
          )}
        </p>
      </div>
    </section>
  );
}
