import { useToast } from "../context/ToastContext.jsx";
import { CLIPBOARD_CLEAR_MS, copyText } from "../utils/clipboard.js";

// `sensitive`: limpa a área de transferência depois de alguns segundos (senhas).
export default function CopyButton({ text, label = "Copiar", message = "Copiado.", sensitive = false }) {
  const showToast = useToast();

  async function handleCopy() {
    try {
      await copyText(text, { sensitive });
      showToast(
        sensitive
          ? `${message} A área de transferência será limpa em ${CLIPBOARD_CLEAR_MS / 1000} s.`
          : message
      );
    } catch {
      showToast("Não foi possível copiar.", "error");
    }
  }

  return (
    <button type="button" className="btn btn-ghost btn-small" onClick={handleCopy} disabled={!text}>
      {label}
    </button>
  );
}
