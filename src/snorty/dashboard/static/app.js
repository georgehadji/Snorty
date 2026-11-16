// htmx does not swap 4xx responses by default. Our 422 answers carry an inline message, so show them.
document.addEventListener("htmx:beforeSwap", (event) => {
  if (event.detail.xhr.status === 422) {
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

  function swapById(html) {
    const incoming = parse(html).firstElementChild;
    const current = incoming && document.getElementById(incoming.id);
    if (!current) return;
    current.replaceWith(incoming);
    activate(incoming);
  }

  function addRows(html) {
    if (!rows) return;
    const fresh = [...parse(html).children];
    const none = rows.querySelector("tr.none");
    if (none) none.remove();
    rows.prepend(...fresh);
    fresh.forEach(activate);
    rows.querySelectorAll("tr[data-alert]").forEach((tr, i) => {
      if (i >= MAX_ROWS) tr.remove();
    });
  }

  function connect() {
    if (source) source.close();
    const query = form ? new URLSearchParams(new FormData(form)).toString() : "";
    source = new EventSource(query ? `/events?${query}` : "/events");
    source.addEventListener("alert", (e) => addRows(e.data));
    source.addEventListener("sensor", (e) => swapById(e.data));
    source.addEventListener("rules", (e) => swapById(e.data));
  }

  if (window.EventSource) connect();
  if (form) {
    form.addEventListener("change", connect);
    form.addEventListener("submit", connect);
  }
})();
