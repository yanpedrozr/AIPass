import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";

// Textos curtos para qualquer pessoa. Os detalhes técnicos ficam em /sobre.
const FEATURES = [
  {
    title: "Cofre cifrado",
    text: "Suas senhas ficam trancadas com criptografia. Só você, com a senha mestra, consegue abrir o cofre.",
  },
  {
    title: "Força por IA",
    text: "Uma inteligência artificial diz se cada senha é fraca, média ou forte.",
  },
  {
    title: "Vazamentos",
    text: "Descubra se alguma senha sua já apareceu em vazamentos de dados na internet.",
  },
  {
    title: "Similaridade",
    text: "Avisamos quando uma senha é só uma pequena variação de uma senha já vazada.",
  },
  {
    title: "Alertas",
    text: "Veja quais senhas precisam ser trocadas e receba dicas do que fazer.",
  },
  {
    title: "Gerador",
    text: "Crie senhas fortes e difíceis de adivinhar com um clique.",
  },
];

export default function Home() {
  const { isAuthenticated } = useAuth();

  return (
    <section>
      <div className="hero">
        <h1>AIPass</h1>
        <p className="tagline">Gerenciador de senhas com inteligência artificial</p>
        <p className="lead">
          Guarde suas senhas com criptografia forte e descubra quais delas estão fracas, vazadas ou
          repetidas entre serviços.
        </p>
        <div className="hero-actions">
          {isAuthenticated ? (
            <>
              <Link to="/cofre" className="btn btn-primary">Abrir cofre</Link>
              <Link to="/analisar" className="btn btn-ghost">Analisar uma senha</Link>
            </>
          ) : (
            <>
              <Link to="/cadastro" className="btn btn-primary">Criar conta</Link>
              <Link to="/entrar" className="btn btn-secondary">Entrar</Link>
            </>
          )}
        </div>
      </div>

      <div className="feature-cards">
        {FEATURES.map((feature) => (
          <div key={feature.title} className="card">
            <h3>{feature.title}</h3>
            <p className="muted">{feature.text}</p>
          </div>
        ))}
      </div>

      <p className="home-about">
        <Link to="/sobre">Como o AIPass funciona por dentro →</Link>
      </p>
    </section>
  );
}
