// Repopulate the IPsec parameter selects with the chosen vendor's supported
// options, shown in that platform's own terminology. Backend still receives the
// canonical value (option value), so generation stays vendor-neutral.
(function () {
  const dataEl = document.getElementById('vendor-opts');
  const vendorSel = document.querySelector('select[name="vendor"]');
  if (!dataEl || !vendorSel) return;
  const byVendor = JSON.parse(dataEl.textContent);

  // Map form field name -> option category in the vendor catalog.
  const FIELDS = {
    p1_enc: 'encryption', p1_integ: 'integrity', p1_dh: 'dh_groups', p1_ver: 'ike_versions',
    p2_enc: 'encryption', p2_integ: 'integrity', p2_pfs: 'dh_groups', auth_method: 'auth_methods',
  };

  function repopulate(vendor) {
    const cat = byVendor[vendor];
    if (!cat) return;
    for (const [field, key] of Object.entries(FIELDS)) {
      const sel = document.querySelector(`select[name="${field}"]`);
      if (!sel) continue;
      const prev = sel.value;
      const opts = cat[key] || [];
      sel.innerHTML = '';
      let matched = false;
      for (const o of opts) {
        const opt = document.createElement('option');
        opt.value = o.value;
        opt.textContent = `${o.label} — ${o.security}`;
        opt.dataset.sec = o.security;
        if (o.value === prev) { opt.selected = true; matched = true; }
        sel.appendChild(opt);
      }
      // If the previous value isn't supported by this vendor, prefer a strong one.
      if (!matched && opts.length) {
        const strong = opts.find(o => o.security === 'strong') || opts[0];
        sel.value = strong.value;
      }
    }
  }

  vendorSel.addEventListener('change', () => repopulate(vendorSel.value));
  repopulate(vendorSel.value);  // initialize for the default vendor
})();
