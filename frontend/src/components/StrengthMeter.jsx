import { useEffect, useState } from "react";
import useDebouncedValue from "../hooks/useDebouncedValue.js";
import { analyzeStrength } from "../services/api.js";
import { STRENGTHS, STRENGTH_CLASS, formatPercent } from "../utils/labels.js";

const MAX_ANALYZED_LENGTH = 128;

// Força da senha pelo Random Forest do backend, atualizada enquanto o usuário
// digita (com atraso, para não mandar uma requisição por tecla).
export default function StrengthMeter({ password }) {
  const debounced = useDebouncedValue(password, 400);
  const [state, setState] = useState({ status: "idle" });

  useEffect(() => {
    if (!debounced) {
      setState({ status: "idle" });
      return undefined;
    }
    if (debounced.length > MAX_ANALYZED_LENGTH) {
      setState({ status: "long" });
      return undefined;
    }
    let active = true;
    setState((current) => ({ ...current, status: "loading" }));
    analyzeStrength(debounced)
      .then((result) => active && setState({ status: "done", result }))
      .catch((error) => active && setState({ status: "error", message: error.message }));
    return () => {
      active = false;
    };
  }, [debounced]);

  if (!password || state.status === "idle") return null;

  if (state.status === "long") {
    return <p className="meter-caption">Senha muito longa: forte pelo comprimento.</p>;
  }
  if (state.status === "error") {
    return <p className="meter-caption muted">Análise de força indisponível: {state.message}</p>;
  }

  const result = state.result;
  const level = result ? STRENGTHS.indexOf(result.strength) + 1 : 0;
  const className = result ? STRENGTH_CLASS[result.strength] : "";
  return (
    <div className={`meter ${state.status === "loading" ? "is-loading" : ""}`} aria-live="polite">
      <div className="meter-bar">
        {STRENGTHS.map((strength, i) => (
          <span key={strength} className={i < level ? `filled ${className}` : ""} />
        ))}
      </div>
      <p className="meter-caption">
        {result ? (
          <>
            Força (IA): <strong className={`text-${className}`}>{result.strength}</strong>
            {" · "}confiança de {formatPercent(result.probabilities[result.strength])}
          </>
        ) : (
          "Analisando..."
        )}
      </p>
    </div>
  );
}
