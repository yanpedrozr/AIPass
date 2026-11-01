import { useState } from "react";
import { Link } from "react-router-dom";
import { RiskBadge, StrengthBadge } from "../components/Badges.jsx";
import PasswordInput from "../components/PasswordInput.jsx";
import { analyzeStrength, checkBreach, checkSimilarity } from "../services/api.js";
import {
  FEATURE_LABELS,
  PATTERN_FEATURES,
  PATTERN_LABELS,
  STRENGTHS,
  STRENGTH_CLASS,
  formatNumber,
  formatPercent,
} from "../utils/labels.js";

function verdict({ strength, breach, similarity }) {
  if (breach.value?.pwned) {
    return { className: "weak", title: "Não use esta senha", text: "Ela já apareceu em vazamentos e está nas listas usadas por atacantes." };
  }
  if (strength.value?.strength === "fraca" || similarity.value?.risk === "alto") {
    return { className: "weak", title: "Senha arriscada", text: "Ela seria adivinhada rapidamente em um ataque de dicionário." };
  }
  if (strength.value?.strength === "média" || similarity.value?.risk === "médio") {
    return { className: "medium", title: "Pode melhorar", text: "Aumente o comprimento e evite palavras e padrões comuns." };
  }
  if (strength.value) {
    return { className: "strong", title: "Boa senha", text: "Forte, sem vazamentos conhecidos e sem semelhança com senhas vazadas." };
  }
  return null;
}

function Failed({ result }) {
  return <p className="notice notice-warning">Indisponível: {result.error.message}</p>;
}

function StrengthResult({ result }) {
  if (result.error) return <Failed result={result} />;
  const { strength, probabilities, features } = result.value;
  const patterns = PATTERN_FEATURES.filter((name) => features[name]);
  return (
    <>
      <p>
        Classificação: <StrengthBadge strength={strength} />
      </p>
      <div className="prob-bars">
        {STRENGTHS.map((label) => (
          <div key={label} className="prob-row">
            <span>{label}</span>
            <div className="prob-track">
              <div
                className={`prob-fill fill-${STRENGTH_CLASS[label]}`}
                style={{ width: formatPercent(probabilities[label]) }}
              />
            </div>
            <span className="prob-value">{formatPercent(probabilities[label])}</span>
          </div>
        ))}
      </div>
      {patterns.length > 0 && (
        <p className="small">
          <strong>Padrões encontrados:</strong>{" "}
          {patterns.map((name) => PATTERN_LABELS[name]).join(", ")}.
        </p>
      )}
      <details>
        <summary>Atributos usados pelo modelo</summary>
        <dl className="feature-grid">
          {Object.entries(features).map(([name, value]) => (
            <div key={name} className={PATTERN_FEATURES.includes(name) && value ? "flagged" : ""}>
              <dt>{FEATURE_LABELS[name] ?? name}</dt>
              <dd>{name === "is_common_password" || name === "contains_year" ? (value ? "sim" : "não") : value}</dd>
            </div>
          ))}
        </dl>
      </details>
    </>
  );
}

function BreachResult({ result }) {
  if (result.error) return <Failed result={result} />;
  const { pwned, count } = result.value;
  return pwned ? (
    <p className="big-stat text-weak">
      Encontrada <strong>{formatNumber(count)}</strong> vez(es) em vazamentos.
    </p>
  ) : (
    <p className="big-stat text-strong">Não encontrada em vazamentos conhecidos.</p>
  );
}

function SimilarityResult({ result }) {
  if (result.error) return <Failed result={result} />;
  const { risk, similarity, similar_passwords: similar, leaked_base: base } = result.value;
  return (
    <>
      <p>
        Risco: <RiskBadge risk={risk} /> · maior similaridade: <strong>{formatPercent(similarity)}</strong>
      </p>
      {base && (
        <p className="small">
          {base.exact
            ? "É uma senha vazada conhecida"
            : "É uma variação de uma senha vazada conhecida"}
          {base.transformations.length > 0 && <> ({base.transformations.join(", ")})</>}.
        </p>
      )}
      {similar.length > 0 && (
        <>
          <p className="small muted">Senhas vazadas mais parecidas (base pública RockYou/SecLists):</p>
          <ul className="similar-list">
            {similar.map((item) => (
              <li key={item.password}>
                <code>{item.password}</code>
                <div className="prob-track">
                  <div className="prob-fill fill-accent" style={{ width: formatPercent(item.similarity) }} />
                </div>
                <span className="prob-value">{formatPercent(item.similarity)}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  );
}

export default function Analyzer() {
  const [password, setPassword] = useState("");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    if (!password) return;
    setLoading(true);
    const settled = await Promise.allSettled([
      analyzeStrength(password),
      checkBreach(password),
      checkSimilarity(password),
    ]);
    const [strength, breach, similarity] = settled.map((r) =>
      r.status === "fulfilled" ? { value: r.value } : { error: r.reason }
    );
    setResults({ strength, breach, similarity });
    setLoading(false);
  }

  function handleChange(value) {
    setPassword(value);
    setResults(null);
  }

  const summary = results && verdict(results);

  return (
    <section>
      <div className="page-header">
        <div>
          <h1>Analisar uma senha</h1>
          <p className="muted">
            Três análises em uma: força por machine learning, vazamentos no Have I Been Pwned e
            similaridade com senhas vazadas. A senha não é armazenada, e ao HIBP vão só os 5
            primeiros caracteres do hash SHA-1 dela (k-anonimato).
          </p>
        </div>
      </div>

      <form className="card form analyzer-form" onSubmit={handleSubmit}>
        <label htmlFor="analyze-password">Senha</label>
        <div className="analyzer-row">
          <PasswordInput id="analyze-password" value={password} onChange={handleChange} maxLength={128} />
          <button type="submit" className="btn btn-primary" disabled={!password || loading}>
            {loading ? "Analisando..." : "Analisar"}
          </button>
        </div>
      </form>

      {summary && (
        <div className={`card verdict verdict-${summary.className}`}>
          <h2>{summary.title}</h2>
          <p>{summary.text}</p>
          {summary.className !== "strong" && (
            <Link to="/gerador" className="btn btn-secondary btn-small">Gerar uma senha forte</Link>
          )}
        </div>
      )}

      {results && (
        <div className="result-grid">
          <div className="card">
            <h2>Força (Random Forest)</h2>
            <StrengthResult result={results.strength} />
          </div>
          <div className="card">
            <h2>Vazamentos (HIBP)</h2>
            <BreachResult result={results.breach} />
          </div>
          <div className="card">
            <h2>Similaridade com vazamentos</h2>
            <SimilarityResult result={results.similarity} />
          </div>
        </div>
      )}
    </section>
  );
}
