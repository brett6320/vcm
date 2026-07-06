// Theme selection: system (default) | light | dark. Persisted in localStorage.
// "system" is resolved to light/dark so Pico and our CSS variables (both keyed
// off data-theme=light|dark) stay in agreement.
(function () {
  function resolve(pref) {
    if (pref === 'light' || pref === 'dark') return pref;
    return (window.matchMedia &&
      window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
  }
  function apply(pref) {
    document.documentElement.setAttribute('data-theme', resolve(pref));
  }
  var sel = document.getElementById('theme-select');
  var pref = localStorage.getItem('vcm-theme') || 'system';
  if (sel) {
    sel.value = pref;
    sel.addEventListener('change', function () {
      localStorage.setItem('vcm-theme', sel.value);
      apply(sel.value);
    });
  }
  apply(pref);
  // Re-resolve when the OS theme flips while in "system" mode.
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
      if ((localStorage.getItem('vcm-theme') || 'system') === 'system') apply('system');
    });
  }
})();
