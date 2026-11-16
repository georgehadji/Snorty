// htmx does not swap 4xx responses by default. Our 422 (bad input) and 409 (not possible right now)
// answers carry an inline message, so show them.
document.addEventListener("htmx:beforeSwap", (event) => {
  if (event.detail.xhr.status === 422 || event.detail.xhr.status === 409) {
    event.detail.shouldSwap = true;
    event.detail.isError = false;
  }
});

// Live updates: /events streams alert rows, the sensor card and the rules summary as HTML.
(() => {
  const MAX_ROWS = 200;
  const rows = document.getElementById("alert-rows");
  const form = document.getElementById("alert-filters");
  let source = null;

  const parse = (html) => {
    const t = document.createElement("template");
    t.innerHTML = html.trim();
    return t.content;
  };
  const activate = (el) => {
    if (window.htmx) window.htmx.process(el);
  };

  const TONES = ["ok", "warn", "bad", "idle"];
  const GROUP_GAP = 15 * 60;  // seconds; keep in step with views.GROUP_GAP

  function swapById(html) {
    const incoming = parse(html).firstElementChild;
    const current = incoming && document.getElementById(incoming.id);
    if (!current) return;
    current.replaceWith(incoming);
    activate(incoming);
  }

  // The header shows the sensor state on every page; the sensor card carries the new one.
  function updateStatus(html) {
    const pill = parse(html).querySelector(".pill");
    const top = document.getElementById("top-status");
    if (!pill || !top) return;
    top.classList.remove(...TONES);
    top.classList.add(...TONES.filter((c) => pill.classList.contains(c)));
    top.querySelector(".txt").textContent = `Sensor ${pill.textContent.trim().toLowerCase()}`;
  }

  function relative(iso) {
    const secs = (Date.now() - Date.parse(iso)) / 1000;
    if (!(secs >= 0) || secs >= 86400) return null;
    if (secs < 45) return "just now";
    if (secs < 3600) return `${Math.round(secs / 60)} min ago`;
    return `${Math.floor(secs / 3600)} h ago`;
  }
  function refreshTimes() {
    document.querySelectorAll("time.rel").forEach((el) => {
      const text = relative(el.dateTime);
      if (text) el.textContent = text;
    });
  }

  function flash(tr) {
    tr.classList.remove("fresh");
    void tr.offsetWidth;  // restart the animation
    tr.classList.add("fresh");
  }

  // A repeat of the newest row's event grows its counter instead of adding a row.
  function mergeInto(top, tr) {
    const count = Number(top.dataset.count || 1) + Number(tr.dataset.count || 1);
    top.dataset.count = String(count);
    top.dataset.epoch = tr.dataset.epoch;
    const when = top.querySelector("td.when time");
    const next = tr.querySelector("td.when time");
    when.dateTime = next.dateTime;
    when.title = next.title;
    when.textContent = next.textContent;
    let badge = top.querySelector(".count");
    if (!badge) {
      badge = document.createElement("span");
      badge.className = "count";
      (top.querySelector("summary") || top.children[2]).append(" ", badge);
    }
    const secs = Number(tr.dataset.epoch) - Number(top.dataset.first);
    const span = secs < 60 ? "" : secs < 3600 ? ` over ${Math.round(secs / 60)} min` : ` over ${Math.floor(secs / 3600)} h`;
    badge.textContent = `×${count}${span}`;
    flash(top);
  }

  function addRows(html) {
    if (!rows) return;
    const none = rows.querySelector("tr.none");
    if (none) none.remove();
    for (const tr of [...parse(html).children].reverse()) {
      const top = rows.querySelector("tr[data-alert]");
      const close = top && Number(tr.dataset.epoch) - Number(top.dataset.epoch) <= GROUP_GAP;
      if (top && close && top.dataset.key === tr.dataset.key) {
        mergeInto(top, tr);
      } else {
        rows.prepend(tr);
        activate(tr);
        flash(tr);
      }
    }
    rows.querySelectorAll("tr[data-alert]").forEach((tr, i) => {
      if (i >= MAX_ROWS) tr.remove();
    });
    refreshTimes();
  }

  // After "Load more", move focus to the first new row so keyboard users keep their place.
  let loadedAfter = null;
  document.addEventListener("htmx:beforeRequest", (e) => {
    const more = e.detail.elt.closest("#more");
    loadedAfter = more ? more.previousElementSibling : null;
  });
  document.addEventListener("htmx:afterSettle", () => {
    const next = loadedAfter && loadedAfter.nextElementSibling;
    loadedAfter = null;
    if (next) {
      next.tabIndex = -1;
      next.focus();
    }
  });

  function setLive(on) {
    const el = document.getElementById("live");
    if (!el) return;
    el.hidden = on;  // shown only while the stream is down
  }

  function connect() {
    if (source) source.close();
    const query = form ? new URLSearchParams(new FormData(form)).toString() : "";
    source = new EventSource(query ? `/events?${query}` : "/events");
    source.addEventListener("open", () => setLive(true));
    source.addEventListener("error", () => setLive(false));
    source.addEventListener("alert", (e) => addRows(e.data));
    source.addEventListener("sensor", (e) => {
      updateStatus(e.data);
      swapById(e.data);
    });
    source.addEventListener("rules", (e) => swapById(e.data));
  }

  // A failed request says so, instead of leaving the page looking unchanged.
  function fail(text) {
    const box = document.getElementById("flash");
    if (!box) return;
    box.textContent = text;
    box.className = "flash bad";
  }
  document.addEventListener("htmx:responseError", (e) => fail(`Request failed (${e.detail.xhr.status}).`));
  document.addEventListener("htmx:sendError", () => fail("Could not reach Snorty."));

  // Colour theme: auto follows the system; the button cycles auto, light, dark.
  const THEMES = ["auto", "light", "dark"];
  const themeBtn = document.getElementById("theme");
  function setTheme(name) {
    if (name === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.dataset.theme = name;
    if (themeBtn) {
      themeBtn.textContent = `Theme: ${name}`;
      themeBtn.setAttribute("aria-label", `Colour theme: ${name}`);
    }
    try { localStorage.setItem("theme", name); } catch (_) { /* private mode */ }
  }
  let saved = "auto";
  try { saved = localStorage.getItem("theme") || "auto"; } catch (_) { /* private mode */ }
  setTheme(THEMES.includes(saved) ? saved : "auto");
  if (themeBtn) {
    themeBtn.addEventListener("click", () => {
      const now = document.documentElement.dataset.theme || "auto";
      setTheme(THEMES[(THEMES.indexOf(now) + 1) % THEMES.length]);
    });
  }

  // Copy buttons (data-copy): put the text on the clipboard, say so on the button.
  document.addEventListener("click", async (e) => {
    const btn = e.target instanceof Element ? e.target.closest("button[data-copy]") : null;
    if (!btn) return;
    const label = btn.textContent;
    let ok = true;
    try { await navigator.clipboard.writeText(btn.dataset.copy || ""); } catch (_) { ok = false; }
    if (!ok) {
      const code = btn.parentElement && btn.parentElement.querySelector("code");
      if (code) window.getSelection().selectAllChildren(code);
    }
    btn.textContent = ok ? "Copied" : "Press Ctrl+C";
    setTimeout(() => { btn.textContent = label; }, 1500);
  });

  refreshTimes();
  setInterval(refreshTimes, 30000);
  if (window.EventSource) connect();
  if (form) {
    form.addEventListener("change", connect);
    form.addEventListener("submit", connect);
  }
})();

// Pcap upload: send the chosen file as a raw body, then show the result and refresh the picker.
(() => {
  const input = document.getElementById("pcap-upload");
  if (!input) return;
  input.addEventListener("change", async () => {
    const file = input.files && input.files[0];
    if (!file) return;
    const headers = JSON.parse(document.body.getAttribute("hx-headers") || "{}");
    const url = "/lab/pcaps?name=" + encodeURIComponent(file.name);
    const t = document.createElement("template");
    try {
      const response = await fetch(url, { method: "POST", headers, body: file });
      t.innerHTML = (await response.text()).trim();
    } catch (err) {
      t.innerHTML = '<div id="flash" class="flash bad" role="status">Upload failed.</div>';
    }
    for (const el of Array.from(t.content.children)) {
      const current = el.id && document.getElementById(el.id);
      if (!current) continue;
      current.replaceWith(el);
      if (window.htmx) window.htmx.process(el);
    }
    input.value = "";
  });
})();
