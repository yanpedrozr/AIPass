import { useState } from "react";

// Campo de senha com botão para mostrar/ocultar.
export default function PasswordInput({ id, value, onChange, autoComplete = "off", ...props }) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="input-group">
      <input
        id={id}
        type={visible ? "text" : "password"}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        autoComplete={autoComplete}
        spellCheck={false}
        autoCapitalize="off"
        className="mono"
        {...props}
      />
      <button
        type="button"
        className="input-addon"
        onClick={() => setVisible((v) => !v)}
        aria-label={visible ? "Ocultar senha" : "Mostrar senha"}
        title={visible ? "Ocultar senha" : "Mostrar senha"}
      >
        {visible ? "Ocultar" : "Mostrar"}
      </button>
    </div>
  );
}
