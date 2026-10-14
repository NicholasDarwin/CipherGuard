import { useEffect, useState } from "react";

const KEY = "cg-theme";
export const THEMES = ["dark", "light", "system"];

function read() {
  try {
    return localStorage.getItem(KEY) || "dark";
  } catch {
    return "dark";
  }
}

function apply(pref) {
  const dark = pref === "system" ? !window.matchMedia("(prefers-color-scheme: light)").matches : pref !== "light";
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", dark ? "#0b0d10" : "#f6f7f9");
}

/** Theme preference: dark (default), light, or follow the system. */
export function useTheme() {
  const [theme, setTheme] = useState(read);

  useEffect(() => {
    apply(theme);
    try {
      localStorage.setItem(KEY, theme);
    } catch {
      /* preference just won't persist */
    }
    if (theme !== "system") return;
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = () => apply("system");
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [theme]);

  return [theme, setTheme];
}
