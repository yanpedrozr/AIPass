import { createContext, useCallback, useContext, useState } from "react";

const ToastContext = createContext(() => {});
const TOAST_DURATION_MS = 4000;
let nextId = 1;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const showToast = useCallback((message, type = "success") => {
    const id = nextId++;
    setToasts((current) => [...current, { id, message, type }]);
    setTimeout(
      () => setToasts((current) => current.filter((toast) => toast.id !== id)),
      TOAST_DURATION_MS
    );
  }, []);

  return (
    <ToastContext.Provider value={showToast}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast toast-${toast.type}`}>
            {toast.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}
