import { useCallback, useEffect, useState } from "react";
import { getSecurityReport, listCredentials } from "../services/api.js";

// Credenciais do cofre e relatório de segurança. A lista chega rápido; o
// relatório consulta o HIBP para cada senha e pode levar alguns segundos, por
// isso é carregado à parte e o anterior continua na tela enquanto atualiza.
export default function useVault() {
  const [credentials, setCredentials] = useState(null);
  const [error, setError] = useState(null);
  const [report, setReport] = useState(null);
  const [reportError, setReportError] = useState(null);
  const [reportLoading, setReportLoading] = useState(false);

  const loadCredentials = useCallback(async () => {
    try {
      const data = await listCredentials();
      setCredentials(data.credentials);
      setError(null);
    } catch (err) {
      // 401 já leva de volta ao login (AuthContext)
      if (err.status !== 401) setError(err.message);
    }
  }, []);

  const loadReport = useCallback(async () => {
    setReportLoading(true);
    try {
      setReport({ ...(await getSecurityReport()), analyzedAt: new Date() });
      setReportError(null);
    } catch (err) {
      if (err.status !== 401) setReportError(err.message);
    } finally {
      setReportLoading(false);
    }
  }, []);

  const refresh = useCallback(() => {
    loadCredentials();
    loadReport();
  }, [loadCredentials, loadReport]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const findCredential = useCallback(
    (id) => credentials?.find((credential) => credential.id === id) ?? null,
    [credentials]
  );

  return {
    credentials,
    error,
    report,
    reportError,
    reportLoading,
    refresh,
    loadReport,
    findCredential,
  };
}
