import { Link } from "react-router-dom";

// Detalhes técnicos de cada recurso resumido nos cartões da página inicial.
const SECTIONS = [
  {
    title: "Cofre cifrado",
    items: [
      "As credenciais são cifradas com AES-256-GCM, com um nonce aleatório de 12 bytes exclusivo para cada credencial e renovado a cada edição.",
      "A chave do cofre é derivada da senha mestra com PBKDF2-HMAC-SHA256 (600 mil iterações, recomendação da OWASP) e fica só na memória do servidor enquanto você está logado.",
      "A senha mestra nunca é armazenada. Nada da credencial (serviço, usuário e senha) fica em texto puro no banco.",
    ],
  },
  {
    title: "Força por IA",
    items: [
      "Um Random Forest (scikit-learn) treinado com senhas reais vazadas da RockYou classifica cada senha como fraca, média ou forte.",
      "O modelo olha 12 atributos: comprimento, tipos de caractere, entropia, presença em listas de senhas comuns, sequências (abc, 123, qwerty), repetições e anos.",
      "No conjunto de teste, acertou 80,9% das senhas (F1 macro de 0,811).",
    ],
  },
  {
    title: "Vazamentos",
    items: [
      "Consulta à base Pwned Passwords do Have I Been Pwned, com centenas de milhões de senhas vazadas.",
      "Usa k-anonimato: só os 5 primeiros caracteres do hash SHA-1 da senha são enviados, e a comparação final é feita no servidor. A senha nunca sai do servidor.",
    ],
  },
  {
    title: "Similaridade",
    items: [
      "Cada senha vira um vetor TF-IDF de n-gramas de caracteres e é comparada, por similaridade do cosseno (k-NN), com cerca de 110 mil senhas vazadas.",
      "Também detecta a palavra-base vazada com maiúsculas, leet e números ou símbolos no fim, como Dragon2024! a partir de dragon.",
    ],
  },
  {
    title: "Alertas",
    items: [
      "Junta os três analisadores e aponta senhas vazadas, fracas, curtas ou parecidas com vazamentos.",
      "Detecta senhas reutilizadas ou muito parecidas entre os seus serviços, a porta de entrada do credential stuffing.",
      "Cada alerta tem uma gravidade (crítico, alto, médio ou baixo) e uma recomendação, e nunca mostra a senha.",
    ],
  },
  {
    title: "Gerador",
    items: [
      "As senhas são geradas com o módulo secrets do Python, um gerador criptograficamente seguro.",
      "Sempre há pelo menos um caractere de cada tipo escolhido, sem viés (amostragem por rejeição), e a entropia exata é calculada em bits.",
    ],
  },
];

export default function About() {
  return (
    <section className="about">
      <div className="page-header">
        <div>
          <h1>Como o AIPass funciona</h1>
          <p className="muted">Os detalhes técnicos por trás de cada recurso.</p>
        </div>
      </div>

      {SECTIONS.map((section) => (
        <div key={section.title} className="card">
          <h2>{section.title}</h2>
          <ul>
            {section.items.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      ))}

      <p>
        <Link to="/">← Voltar ao início</Link>
      </p>
    </section>
  );
}
