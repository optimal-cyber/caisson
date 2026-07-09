/* Caisson landing page — minimal progressive enhancement, no framework. */
(function () {
  "use strict";

  // Reveal sections as they scroll into view (respects reduced-motion).
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var targets = document.querySelectorAll(".section, .strip, .card");

  if (reduce || !("IntersectionObserver" in window)) {
    targets.forEach(function (el) { el.style.opacity = 1; });
  } else {
    targets.forEach(function (el) {
      el.style.opacity = 0;
      el.style.transform = "translateY(16px)";
      el.style.transition = "opacity .5s ease, transform .5s ease";
    });
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          e.target.style.opacity = 1;
          e.target.style.transform = "none";
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.12 });
    targets.forEach(function (el) { io.observe(el); });
  }

  // Active-section highlight in the nav.
  var links = Array.prototype.slice.call(document.querySelectorAll(".nav-links a[href^='#']"));
  var map = {};
  links.forEach(function (l) {
    var id = l.getAttribute("href").slice(1);
    var sec = document.getElementById(id);
    if (sec) map[id] = l;
  });
  if ("IntersectionObserver" in window && Object.keys(map).length) {
    var navIo = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting && map[e.target.id]) {
          links.forEach(function (l) { l.style.color = ""; });
          map[e.target.id].style.color = "var(--vault-chrome)";
        }
      });
    }, { rootMargin: "-45% 0px -50% 0px" });
    Object.keys(map).forEach(function (id) {
      navIo.observe(document.getElementById(id));
    });
  }
})();
