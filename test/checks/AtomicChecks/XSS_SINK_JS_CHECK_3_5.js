// HTML sinks beyond innerHTML: generated iframe documents, frame documents and parsed fragments
function exportToPdf(html) {
  const frame = document.createElement("iframe");
  frame.srcdoc = html;
  frame.contentDocument.write(html);
  frame.setAttribute("srcdoc", html);
  document.createRange().createContextualFragment(html);
  return jsx("iframe", { srcDoc: html });
}
