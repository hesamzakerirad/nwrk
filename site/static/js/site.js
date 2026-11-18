/* nwrk site: theme toggle, copy buttons, dithered plates, example runs.
   Everything here is an enhancement; the pages work without it. */
(function () {
  "use strict";
  var d = document, root = d.documentElement;
  root.classList.add("js");
  var reduce = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  var body = d.body;
  var L = function (k, fb) { return body.getAttribute("data-l-" + k) || fb; };

  /* ---- theme ---- */
  var toggle = d.querySelector("[data-theme-toggle]");
  var tlabel = d.querySelector("[data-theme-label]");
  function current() {
    var t = root.getAttribute("data-theme");
    if (t) return t;
    return window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  function label() {
    if (!toggle) return;
    toggle.setAttribute("aria-checked", current() === "dark" ? "true" : "false");
    if (tlabel) tlabel.textContent = L("theme", "theme") + ": " + current();
  }
  if (toggle) {
    label();
    toggle.addEventListener("click", function () {
      var next = current() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("nwrk-theme", next); } catch (e) {}
      label();
    });
  }

  /* ---- copy ---- */
  function copyText(text, btn) {
    var done = function () {
      var old = btn.textContent;
      btn.textContent = L("copied", "copied");
      setTimeout(function () { btn.textContent = old; }, 1400);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () {});
      return;
    }
    var ta = d.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    d.body.appendChild(ta); ta.select();
    try { d.execCommand("copy"); done(); } catch (e) {}
    d.body.removeChild(ta);
  }
  function addCopy(host, getText) {
    var b = d.createElement("button");
    b.type = "button"; b.className = "copy"; b.textContent = L("copy", "copy");
    b.addEventListener("click", function () { copyText(getText(), b); });
    host.appendChild(b);
  }
  d.querySelectorAll("[data-copy]").forEach(function (row) {
    addCopy(row, function () { return row.getAttribute("data-copy"); });
  });
  d.querySelectorAll(".prose pre, .docs-main pre").forEach(function (pre) {
    addCopy(pre, function () {
      var c = pre.querySelector("code");
      return (c ? c.textContent : pre.textContent).replace(/^[$>] /gm, "");
    });
  });

  /* ---- segmented controls ---- */
  function wireSeg(group, onSelect) {
    var tabs = group.querySelectorAll('.seg [role="tab"]');
    var panels = Array.prototype.map.call(tabs, function (t) { return d.getElementById(t.getAttribute("aria-controls")); });
    function select(i, user) {
      tabs.forEach(function (tb, j) {
        tb.setAttribute("aria-selected", j === i ? "true" : "false");
        tb.tabIndex = j === i ? 0 : -1;
      });
      panels.forEach(function (p, j) { if (p) p.hidden = j !== i; });
      if (onSelect) onSelect(panels[i], !!user);
    }
    tabs.forEach(function (tb, i) {
      tb.addEventListener("click", function () { select(i, true); });
      tb.addEventListener("keydown", function (e) {
        var n = null;
        if (e.key === "ArrowRight" || e.key === "ArrowDown") n = (i + 1) % tabs.length;
        if (e.key === "ArrowLeft" || e.key === "ArrowUp") n = (i + tabs.length - 1) % tabs.length;
        if (n !== null) { e.preventDefault(); tabs[n].focus(); select(n, true); }
      });
    });
    return select;
  }

  /* install: default to the visitor's system */
  var inst = d.querySelector(".install[data-seg-group]");
  if (inst) {
    var pick = wireSeg(inst);
    if (/Windows/i.test(navigator.userAgent)) pick(1, false);
  }

  /* example runs: replay real nw output */
  var timers = [];
  function clear() { timers.forEach(clearTimeout); timers = []; }
  function show(p, fast) {
    clear();
    var ls = Array.prototype.slice.call(p.querySelectorAll("[data-line]"));
    ls.forEach(function (l) { l.classList.remove("on"); });
    if (reduce) { ls.forEach(function (l) { l.classList.add("on"); }); return; }
    var t = 0, cmd = ls[0], full = cmd ? cmd.getAttribute("data-text") : "";
    if (cmd && full && !fast) {
      var type = cmd.querySelector("[data-type]");
      cmd.classList.add("on");
      for (var i = 0; i <= full.length; i++) {
        (function (n) { timers.push(setTimeout(function () { type.textContent = full.slice(0, n); }, t)); })(i);
        t += 24;
      }
      t += 280;
    } else if (cmd) { cmd.classList.add("on"); }
    ls.slice(1).forEach(function (l) {
      timers.push(setTimeout(function () { l.classList.add("on"); }, t));
      t += fast ? 14 : 60;
    });
  }
  var demo = d.querySelector('[data-seg-group="demo"]');
  if (demo) {
    var active = null;
    var start = wireSeg(demo, function (panel, user) { active = panel; if (panel) show(panel, user); });
    start(0, false);
    var tabsEl = demo.querySelectorAll('.seg [role="tab"]');
    var replay = d.querySelector("[data-replay]");
    if (replay) replay.addEventListener("click", function () { if (active) show(active, false); });
    // 1 to 4 switch the example run, unless the visitor is typing somewhere.
    d.addEventListener("keydown", function (e) {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      var t = e.target, tag = t && t.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || (t && t.isContentEditable)) return;
      var n = parseInt(e.key, 10);
      if (n >= 1 && n <= tabsEl.length) { start(n - 1, true); }
    });
  }
  // The trace runs once, when it first scrolls into view.
  var trace = d.querySelector("[data-trace]");
  if (trace) {
    var reduce = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
    var anims = [], visible = false, delay = null;
    // The signal runs down the rail, turns red at tls, and loops. Positions come from the real node centers.
    var buildSignal = function () {
      anims.forEach(function (a) { a.cancel(); });
      anims = [];
      var hops = trace.querySelector(".hops"), probe = trace.querySelector(".probe"), beam = trace.querySelector(".beam");
      var nodes = trace.querySelectorAll(".hop .node");
      if (!hops || !probe || !beam || nodes.length < 4 || !probe.animate) return;
      var base = hops.getBoundingClientRect();
      var pt = function (n) { var r = n.getBoundingClientRect(); return { x: r.left - base.left + r.width / 2, y: r.top - base.top + r.height / 2 }; };
      var y = [0, 1, 2, 3].map(function (i) { return pt(nodes[i]).y; }), x = pt(nodes[0]).x;
      probe.style.left = x + "px"; beam.style.left = x + "px";
      beam.style.top = y[2] + "px"; beam.style.height = (y[3] - y[2]) + "px";
      var G = "var(--ok)", R = "var(--fail)", T = "translateY(", dur = 7200;
      var f = function (o, yy, op, col, sc) { return { offset: o, transform: T + yy + "px) scale(" + (sc || 1) + ")", opacity: op, color: col }; };
      anims.push(probe.animate([
        f(0, y[0], 0, G), f(0.04, y[0], 1, G), f(0.26, y[1], 1, G), f(0.44, y[2], 1, G), f(0.6, y[3], 1, G),
        f(0.61, y[3], 1, R, 1.5), f(0.68, y[3], 1, R, 1), f(0.75, y[3], 1, R, 1.5), f(0.82, y[3], 1, R, 1),
        f(0.9, y[3], 0, R, 1), f(1, y[0], 0, G)
      ], { duration: dur, iterations: Infinity, easing: "ease-in-out" }));
      var pulse = function (o, v) { return { offset: o, opacity: v }; };
      anims.push(beam.animate([
        pulse(0, 0), pulse(0.58, 0), pulse(0.61, 1), pulse(0.66, 0.35), pulse(0.71, 1), pulse(0.76, 0.35), pulse(0.81, 1), pulse(0.9, 0), pulse(1, 0)
      ], { duration: dur, iterations: Infinity }));
      if (!visible) anims.forEach(function (a) { a.pause(); });
    };
    var armSignal = function () {
      if (reduce) return;
      delay = setTimeout(function () { visible = true; buildSignal(); }, 2400);
      var rt;
      window.addEventListener("resize", function () { clearTimeout(rt); rt = setTimeout(function () { if (visible) buildSignal(); }, 150); });
      if ("IntersectionObserver" in window) {
        new IntersectionObserver(function (es) {
          visible = es[0].isIntersecting;
          anims.forEach(function (a) { visible ? a.play() : a.pause(); });
        }, { threshold: 0.2 }).observe(trace);
      }
    };
    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (es) {
        if (es[0].isIntersecting) { trace.classList.add("run"); io.disconnect(); armSignal(); }
      }, { threshold: 0.35 });
      io.observe(trace);
    } else { trace.classList.add("run"); armSignal(); }
  }
  // The latest version comes from the newest GitHub release. If the lookup fails, the built-in version stays.
  var ver = d.querySelector("[data-version]");
  if (ver && window.fetch) {
    fetch(ver.getAttribute("data-api"), { headers: { Accept: "application/vnd.github+json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        if (!j || !j.tag_name) return;
        ver.textContent = j.tag_name;
      })
      .catch(function () {});
  }
})();
