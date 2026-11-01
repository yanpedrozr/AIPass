import { useCallback, useEffect, useState } from "react";
import CopyButton from "../components/CopyButton.jsx";
import { generatePassword } from "../services/api.js";
import { entropyLabel } from "../utils/labels.js";

const CATEGORIES = [
  { name: "uppercase", label: "Maiúsculas (A-Z)" },
  { name: "lowercase", label: "Minúsculas (a-z)" },
  { name: "digits", label: "Números (0-9)" },
  { name: "symbols", label: "Símbolos (!@#$...)" },
];

export default function Generator() {
  const [options, setOptions] = useState({
    length: 16,
    uppercase: true,
    lowercase: true,
    digits: true,
    symbols: true,
  });
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const noCategory = CATEGORIES.every(({ name }) => !options[name]);

  const generate = useCallback(async (currentOptions) => {
    setLoading(true);
    try {
      setResult(await generatePassword(currentOptions));
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  // Gera de novo sempre que as opções mudam.
  useEffect(() => {
    if (noCategory) return undefined;
    const timer = setTimeout(() => generate(options), 150);
    return () => clearTimeout(timer);
  }, [options, noCategory, generate]);

  const strength = result ? entropyLabel(result.entropy_bits) : null;

  return (
    <section>
      <div className="page-header">
        <div>
          <h1>Gerador de senhas</h1>
          <p className="muted">
            Gerado no servidor com o módulo <code>secrets</code> (gerador criptograficamente seguro),
            com pelo menos um caractere de cada tipo escolhido.
          </p>
        </div>
      </div>

      <div className="card generator-output">
        <output className="generated-password mono" aria-live="polite">
          {noCategory ? "Escolha pelo menos um tipo de caractere" : result?.password ?? "..."}
        </output>
        <div className="generator-actions">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => generate(options)}
            disabled={loading || noCategory}
          >
            Gerar outra
          </button>
          <CopyButton text={noCategory ? "" : result?.password} label="Copiar" message="Senha copiada." sensitive />
        </div>
        {strength && !noCategory && (
          <p className="muted small">
            Entropia: <strong>{result.entropy_bits} bits</strong> —{" "}
            <span className={`text-${strength.className}`}>{strength.label}</span>. Cada bit dobra o
            número de tentativas de um ataque de força bruta.
          </p>
        )}
      </div>

      <div className="card form">
        <label htmlFor="gen-length">
          Comprimento: <strong>{options.length}</strong> caracteres
        </label>
        <input
          id="gen-length"
          type="range"
          min={4}
          max={64}
          value={options.length}
          onChange={(e) => setOptions((o) => ({ ...o, length: Number(e.target.value) }))}
        />
        <fieldset className="checkbox-grid">
          <legend>Tipos de caractere</legend>
          {CATEGORIES.map(({ name, label }) => (
            <label key={name} className="checkbox">
              <input
                type="checkbox"
                checked={options[name]}
                onChange={(e) => setOptions((o) => ({ ...o, [name]: e.target.checked }))}
              />
              {label}
            </label>
          ))}
        </fieldset>
        {error && <p className="notice notice-error">{error}</p>}
      </div>
    </section>
  );
}
