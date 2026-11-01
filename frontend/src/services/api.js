const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000/api";

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

// O token fica aqui (e no AuthContext), não é lido de nenhum global do navegador
// a cada request.
let authToken = null;
let unauthorizedHandler = null;

export function setAuthToken(token) {
  authToken = token;
}

// Chamado quando uma rota protegida responde 401 (sessão expirada, logout em
// outra aba ou reinício do backend, que apaga as chaves do cofre da memória).
export function setUnauthorizedHandler(handler) {
  unauthorizedHandler = handler;
}

async function request(path, { method = "GET", body, auth = false } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (auth && authToken) headers.Authorization = `Bearer ${authToken}`;

  let response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
    });
  } catch {
    throw new ApiError(
      "Não foi possível conectar ao servidor. Verifique se o backend está rodando.",
      0
    );
  }

  if (response.status === 204) return null;
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const message = data?.error || `Erro ${response.status} em ${path}`;
    if (auth && (response.status === 401 || response.status === 422)) {
      unauthorizedHandler?.(message);
    }
    throw new ApiError(message, response.status);
  }
  return data;
}

// Saúde
export const getHealth = () => request("/health");

// Autenticação
export const register = (username, masterPassword) =>
  request("/auth/register", {
    method: "POST",
    body: { username, master_password: masterPassword },
  });
export const login = (username, masterPassword) =>
  request("/auth/login", {
    method: "POST",
    body: { username, master_password: masterPassword },
  });
export const logout = () => request("/auth/logout", { method: "POST", auth: true });

// Cofre
export const listCredentials = () => request("/vault", { auth: true });
export const createCredential = (fields) =>
  request("/vault", { method: "POST", body: fields, auth: true });
export const updateCredential = (id, fields) =>
  request(`/vault/${encodeURIComponent(id)}`, { method: "PATCH", body: fields, auth: true });
export const deleteCredential = (id) =>
  request(`/vault/${encodeURIComponent(id)}`, { method: "DELETE", auth: true });
export const getSecurityReport = () => request("/vault/security-report", { auth: true });

// Ferramentas (não exigem login). A senha vai sempre no corpo, nunca na URL.
export const generatePassword = (options) =>
  request("/generator/generate-password", { method: "POST", body: options });
export const analyzeStrength = (password) =>
  request("/analysis", { method: "POST", body: { password } });
export const checkBreach = (password) =>
  request("/breach", { method: "POST", body: { password } });
export const checkSimilarity = (password) =>
  request("/breach/similarity", { method: "POST", body: { password } });
