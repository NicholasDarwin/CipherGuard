(function () {
  try {
    var pref = localStorage.getItem("cg-theme") || "dark";
    var dark = pref === "system" ? !window.matchMedia("(prefers-color-scheme: light)").matches : pref !== "light";
    document.documentElement.dataset.theme = dark ? "dark" : "light";
  } catch (e) {
    /* storage blocked: keep the dark default */
  }
})();
