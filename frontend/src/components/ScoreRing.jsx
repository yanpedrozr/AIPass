// Nota de segurança do cofre (0 a 100) em um anel.
export default function ScoreRing({ score, size = "large" }) {
  const level = score >= 80 ? "strong" : score >= 50 ? "medium" : "weak";
  return (
    <div
      className={`score-ring score-${level} score-${size}`}
      style={{ "--score": score }}
      role="img"
      aria-label={`Nota de segurança: ${score} de 100`}
    >
      <span>{score}</span>
    </div>
  );
}
