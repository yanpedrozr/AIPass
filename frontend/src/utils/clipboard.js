// Tempo até a área de transferência ser limpa depois de copiar uma senha.
export const CLIPBOARD_CLEAR_MS = 30 * 1000;

let lastCopy = 0;

// Copia o texto e, se for sensível, limpa a área de transferência depois de
// CLIPBOARD_CLEAR_MS (a não ser que outra cópia tenha sido feita pelo app).
export async function copyText(text, { sensitive = false } = {}) {
  await navigator.clipboard.writeText(text);
  const copyId = ++lastCopy;
  if (sensitive) {
    setTimeout(() => {
      if (copyId === lastCopy) navigator.clipboard.writeText("").catch(() => {});
    }, CLIPBOARD_CLEAR_MS);
  }
}
