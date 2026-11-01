import { useState } from "react";
import { Link, NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";

export default function Navbar() {
  const { isAuthenticated, user, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const navigate = useNavigate();

  const close = () => setMenuOpen(false);

  async function handleLogout() {
    close();
    await logout("Você saiu. O cofre foi bloqueado.");
    navigate("/entrar");
  }

  return (
    <>
      <header className="navbar">
        <div className="navbar-inner">
          <Link to="/" className="brand" onClick={close}>
            AIPass
          </Link>

          {isAuthenticated && (
            <>
              <button
                type="button"
                className="menu-toggle"
                aria-expanded={menuOpen}
                aria-label="Abrir menu"
                onClick={() => setMenuOpen((open) => !open)}
              >
                ☰
              </button>

              <nav className={`nav-links ${menuOpen ? "open" : ""}`} onClick={close}>
                <NavLink to="/cofre">Cofre</NavLink>
                <NavLink to="/seguranca">Segurança</NavLink>
                <NavLink to="/gerador">Gerador</NavLink>
                <NavLink to="/analisar">Analisar senha</NavLink>
              </nav>
            </>
          )}
        </div>
      </header>

      {/* Inicial do usuário no canto inferior esquerdo. O nome e o botão de
          sair aparecem ao passar o mouse, ou ao tocar/focar a inicial. */}
      {isAuthenticated && (
        <div className="user-dock">
          <button type="button" className="user-dock-avatar" aria-label={`Usuário ${user?.username}`}>
            {user?.username?.charAt(0).toUpperCase()}
          </button>
          <div className="user-dock-details">
            <span className="user-dock-name">{user?.username}</span>
            <button type="button" className="btn btn-ghost btn-small" onClick={handleLogout}>
              Sair
            </button>
          </div>
        </div>
      )}
    </>
  );
}
