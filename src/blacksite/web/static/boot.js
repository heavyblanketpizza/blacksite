// Runs before the stylesheet paints: apply the saved theme and language so night mode
// never flashes white. A separate file, because the page forbids inline scripts.
"use strict";
try {
  const theme = localStorage.getItem("blacksite.theme");
  if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
  const lang = localStorage.getItem("blacksite.lang");
  if (lang) document.documentElement.lang = lang;
} catch (error) { /* storage can be unavailable; the defaults apply */ }
window.BLACKSITE_I18N = document.querySelector('meta[name="blacksite-i18n"]')?.content || "/static/i18n.json";
