import { useSyncExternalStore } from "react";

let toasts = [];
const listeners = new Set();
const emit = () => listeners.forEach((l) => l());

export function toast(message, { tone = "neutral", ms = 3200 } = {}) {
  const id = Math.random().toString(36).slice(2);
  toasts = [...toasts, { id, message, tone }];
  emit();
  setTimeout(() => {
    toasts = toasts.filter((t) => t.id !== id);
    emit();
  }, ms);
}

export function useToasts() {
  return useSyncExternalStore(
    (l) => (listeners.add(l), () => listeners.delete(l)),
    () => toasts
  );
}
