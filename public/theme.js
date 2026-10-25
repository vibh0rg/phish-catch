// Resolve the theme before first paint (saved choice, else the system setting) to avoid a flash.
(function () {
  var theme = null;
  try {
    theme = localStorage.getItem('phishcatch-theme');
  } catch (e) {}
  if (theme !== 'light' && theme !== 'dark') {
    theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  document.documentElement.setAttribute('data-theme', theme);
})();
