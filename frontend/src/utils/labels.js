// Gravidades dos alertas, da mais para a menos grave (mesma ordem do backend).
export const SEVERITIES = ["crítico", "alto", "médio", "baixo"];

export const SEVERITY_CLASS = {
  crítico: "critical",
  alto: "high",
  médio: "medium",
  baixo: "low",
};

export const STRENGTH_CLASS = { fraca: "weak", média: "medium", forte: "strong" };
export const STRENGTHS = ["fraca", "média", "forte"];

export const RISK_CLASS = { alto: "high", médio: "medium", baixo: "low" };

export const ALERT_TYPE_LABELS = {
  breached: "Vazada",
  reused: "Reutilizada",
  leak_variation: "Variação de vazamento",
  weak: "Senha fraca",
  similar: "Senhas parecidas",
  leak_similarity: "Parecida com vazamentos",
  short: "Senha curta",
};

// Atributos extraídos pelo modelo (backend/app/ml_analysis/features.py).
export const FEATURE_LABELS = {
  length: "Comprimento",
  uppercase_count: "Letras maiúsculas",
  lowercase_count: "Letras minúsculas",
  digit_count: "Números",
  special_count: "Símbolos",
  entropy_bits: "Entropia (bits)",
  is_common_password: "Está na lista de senhas comuns",
  common_substring_length: "Maior trecho de senha comum",
  sequence_length: "Maior sequência (abc, 123)",
  keyboard_sequence_length: "Maior sequência de teclado (qwerty)",
  repeated_char_length: "Maior repetição de caractere",
  contains_year: "Contém um ano",
};

// Atributos que indicam um padrão fraco quando são diferentes de zero.
export const PATTERN_LABELS = {
  is_common_password: "está na lista de senhas comuns",
  common_substring_length: "contém uma senha comum",
  sequence_length: "sequência (abc, 123)",
  keyboard_sequence_length: "sequência de teclado (qwerty)",
  repeated_char_length: "caractere repetido",
  contains_year: "contém um ano",
};
export const PATTERN_FEATURES = Object.keys(PATTERN_LABELS);

export function formatNumber(value) {
  return new Intl.NumberFormat("pt-BR").format(value);
}

export function formatPercent(value) {
  return `${Math.round(value * 100)}%`;
}

// Classificação qualitativa da entropia de uma senha aleatória.
export function entropyLabel(bits) {
  if (bits < 40) return { label: "fraca", className: "weak" };
  if (bits < 60) return { label: "razoável", className: "medium" };
  if (bits < 80) return { label: "forte", className: "strong" };
  return { label: "muito forte", className: "strong" };
}
