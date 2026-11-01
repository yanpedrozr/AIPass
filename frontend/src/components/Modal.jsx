import { useEffect, useRef } from "react";

export default function Modal({ title, onClose, children }) {
  const dialogRef = useRef(null);
  // Em ref para o efeito rodar só ao abrir, mesmo que onClose mude a cada render.
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    const previousFocus = document.activeElement;
    dialogRef.current?.querySelector("input, textarea, select, button:not(.icon-button)")?.focus();
    const onKeyDown = (event) => {
      if (event.key === "Escape") onCloseRef.current();
    };
    document.addEventListener("keydown", onKeyDown);
    document.body.classList.add("no-scroll");
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.classList.remove("no-scroll");
      previousFocus?.focus?.();
    };
  }, []);

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title" ref={dialogRef}>
        <div className="modal-header">
          <h2 id="modal-title">{title}</h2>
          <button type="button" className="icon-button" aria-label="Fechar" onClick={onClose}>
            ✕
          </button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}
