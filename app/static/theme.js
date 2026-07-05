// Theme selection: system (default) | light | dark. Persisted in localStorage.
(function () {
  var sel = document.getElementById('theme-select');
  var current = localStorage.getItem('vcm-theme') || 'system';
  if (sel) {
    sel.value = current;
    sel.addEventListener('change', function () {
      localStorage.setItem('vcm-theme', sel.value);
      document.documentElement.setAttribute('data-theme', sel.value);
    });
  }
  // Re-render when the OS theme flips while in "system" mode.
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
      if ((localStorage.getItem('vcm-theme') || 'system') === 'system') {
        document.documentElement.setAttribute('data-theme', 'system');
      }
    });
  }
})();
