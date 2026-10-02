// iframes created in compiled code: one with generated HTML and no sandbox, one JSX frame without a sandbox, one sandboxed
function exportToPdf(html) {
  const frame = document.createElement("iframe");
  frame.srcdoc = html;
  document.body.appendChild(frame);
}
const embed = (url) => jsx("iframe", { src: url, title: "embed" });
function preview(html) {
  const safe = document.createElement("iframe");
  safe.setAttribute("sandbox", "");
  safe.srcdoc = html;
}
