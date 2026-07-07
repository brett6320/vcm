// Progressive enhancement: on panel-heavy pages, make each .card collapsible by
// clicking its heading. Only kicks in when a page has several panels, so simple
// one/two-panel pages are unaffected. Collapsed state persists per page+heading.
//
// A card marked ".card.collapse-default" (or [data-collapse-default]) is a
// non-essential panel (action/creation forms, advanced/danger sections): it
// starts collapsed on first load, but a user's saved choice for that panel is
// always respected. Any page that has such a marked panel is enhanced even if
// it has fewer than the usual panel-heavy threshold, so the default applies.
(function () {
  "use strict";
  var main = document.querySelector("main");
  if (!main) return;
  var cards = Array.prototype.filter.call(
    main.querySelectorAll(".card"),
    function (c) { return c.querySelector("h2, h3, h4"); }
  );
  function isDefaultCollapsed(c) {
    return c.classList.contains("collapse-default") ||
           c.hasAttribute("data-collapse-default");
  }
  var hasMarked = Array.prototype.some.call(cards, isDefaultCollapsed);
  // Enhance panel-heavy pages, or any page that opts in via a marked panel.
  if (cards.length < 4 && !hasMarked) return;

  var pageKey = "vcm:collapse:" + location.pathname;
  var state = {};
  try { state = JSON.parse(localStorage.getItem(pageKey) || "{}"); } catch (e) {}

  function save() {
    try { localStorage.setItem(pageKey, JSON.stringify(state)); } catch (e) {}
  }

  cards.forEach(function (card, i) {
    var heading = card.querySelector("h2, h3, h4");
    if (!heading) return;
    // The direct child of the card that holds the heading stays visible.
    var head = heading;
    while (head.parentNode !== card) head = head.parentNode;
    head.classList.add("card-head");

    card.classList.add("collapsible");
    var key = (heading.textContent || String(i)).trim().slice(0, 60);

    // First load of a non-essential panel: start collapsed. A prior user
    // choice (present in state) always wins — including an explicit expand.
    if (!(key in state) && isDefaultCollapsed(card)) state[key] = true;

    var arrow = document.createElement("span");
    arrow.className = "collapse-arrow";
    heading.insertBefore(arrow, heading.firstChild);
    heading.classList.add("collapse-toggle");
    heading.setAttribute("role", "button");
    heading.setAttribute("tabindex", "0");

    function apply() {
      card.classList.toggle("collapsed", !!state[key]);
      arrow.textContent = state[key] ? "▸ " : "▾ "; // ▸ / ▾
    }
    function toggle() { state[key] = !state[key]; apply(); save(); }

    heading.addEventListener("click", toggle);
    heading.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); }
    });
    apply();
  });
})();
