import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import * as api from "../services/api.js";

const STORAGE_KEY = "pm.session";

// Bloqueia o cofre depois de 10 minutos sem interação.
export const INACTIVITY_LIMIT_MS = 10 * 60 * 1000;
const ACTIVITY_EVENTS = ["mousedown", "keydown", "scroll", "touchstart"];

const AuthContext = createContext(null);

// Expiração do JWT (campo exp), em milissegundos.
function tokenExpiry(token) {
  try {
    const payload = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(payload)).exp * 1000;
  } catch {
    return null;
  }
}

// A sessão fica no sessionStorage: sobrevive a um F5, mas some ao fechar a
// aba. O token sozinho não abre o cofre depois do logout ou de um reinício do
// backend, porque a chave do cofre só existe na memória do servidor.
function loadSession() {
  try {
    const session = JSON.parse(sessionStorage.getItem(STORAGE_KEY));
    if (session?.token && (tokenExpiry(session.token) ?? 0) > Date.now()) {
      api.setAuthToken(session.token);
      return session;
    }
  } catch {
    // sessionStorage indisponível ou corrompido: começa deslogado
  }
  return null;
}

function saveSession(session) {
  try {
    if (session) sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session));
    else sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // sem sessionStorage a sessão dura só até recarregar a página
  }
}

export function AuthProvider({ children }) {
  const [session, setSession] = useState(loadSession);
  const [notice, setNotice] = useState(null);
  const sessionRef = useRef(session);
  sessionRef.current = session;

  const clearSession = useCallback((message = null) => {
    api.setAuthToken(null);
    saveSession(null);
    setSession(null);
    setNotice(message);
  }, []);

  const login = useCallback(async (username, masterPassword) => {
    const data = await api.login(username, masterPassword);
    const next = { token: data.access_token, user: data.user };
    api.setAuthToken(next.token);
    saveSession(next);
    setNotice(null);
    setSession(next);
  }, []);

  const register = useCallback(
    async (username, masterPassword) => {
      await api.register(username, masterPassword);
      await login(username, masterPassword);
    },
    [login]
  );

  const logout = useCallback(
    async (message = null) => {
      if (sessionRef.current) {
        // Apaga a chave do cofre da memória do servidor.
        await api.logout().catch(() => {});
      }
      clearSession(message);
    },
    [clearSession]
  );

  useEffect(() => {
    api.setUnauthorizedHandler((message) => clearSession(message));
    return () => api.setUnauthorizedHandler(null);
  }, [clearSession]);

  // Encerra a sessão quando o token expira.
  useEffect(() => {
    if (!session) return undefined;
    const remaining = (tokenExpiry(session.token) ?? 0) - Date.now();
    const timer = setTimeout(
      () => clearSession("Sua sessão expirou. Faça login novamente."),
      Math.max(remaining, 0)
    );
    return () => clearTimeout(timer);
  }, [session, clearSession]);

  // Bloqueio automático por inatividade.
  useEffect(() => {
    if (!session) return undefined;
    let timer;
    const reset = () => {
      clearTimeout(timer);
      timer = setTimeout(
        () => logout("Cofre bloqueado após 10 minutos sem atividade."),
        INACTIVITY_LIMIT_MS
      );
    };
    reset();
    ACTIVITY_EVENTS.forEach((event) => window.addEventListener(event, reset, { passive: true }));
    return () => {
      clearTimeout(timer);
      ACTIVITY_EVENTS.forEach((event) => window.removeEventListener(event, reset));
    };
  }, [session, logout]);

  const value = {
    user: session?.user ?? null,
    isAuthenticated: Boolean(session),
    notice,
    login,
    register,
    logout,
  };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  return useContext(AuthContext);
}
