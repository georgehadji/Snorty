// htmx does not swap 4xx responses by default. Our 422 answers carry an inline message, so show them.
document.addEventListener("htmx:beforeSwap", (event) => {
  if (event.detail.xhr.status === 422) {
    event.detail.shouldSwap = true;
    event.detail.isError = false;
  }
});
// Live updates over /events are added in the SSE task.
