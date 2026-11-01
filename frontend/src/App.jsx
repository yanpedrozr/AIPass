import { Link, Route, Routes, useLocation } from "react-router-dom";
import Navbar from "./components/Navbar.jsx";
import ProtectedRoute from "./components/ProtectedRoute.jsx";
import About from "./pages/About.jsx";
import Analyzer from "./pages/Analyzer.jsx";
import Auth from "./pages/Auth.jsx";
import Generator from "./pages/Generator.jsx";
import Home from "./pages/Home.jsx";
import Security from "./pages/Security.jsx";
import Vault from "./pages/Vault.jsx";

function NotFound() {
  return (
    <section className="card empty-state">
      <h1>Página não encontrada</h1>
      <Link to="/" className="btn btn-primary">Voltar ao início</Link>
    </section>
  );
}

export default function App() {
  // A página inicial é uma tela de apresentação, sem a barra superior.
  const { pathname } = useLocation();
  return (
    <>
      {pathname !== "/" && <Navbar />}
      <main className="container">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/sobre" element={<About />} />
          <Route path="/entrar" element={<Auth mode="login" />} />
          <Route path="/cadastro" element={<Auth mode="register" />} />
          <Route path="/cofre" element={<ProtectedRoute><Vault /></ProtectedRoute>} />
          <Route path="/seguranca" element={<ProtectedRoute><Security /></ProtectedRoute>} />
          <Route path="/gerador" element={<ProtectedRoute><Generator /></ProtectedRoute>} />
          <Route path="/analisar" element={<ProtectedRoute><Analyzer /></ProtectedRoute>} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
    </>
  );
}
