// export templates that put note data into markup as is (Notesnook CVE-2026-42090)
function buildHtml(data) {
  return `<!doctype html><html><head><title>${data.title}</title><meta name="description" content="${data.headline}"></head>
<body><h1>${data.title}</h1>${data.content}</body></html>`;
}
const tags = (note) => `<ul class="tags">${note.tags.join(", ")}</ul>`;
// not reported: numbers and sizes, a tagged (escaping) template, no markup at all
const bar = (width, i) => `<div style="width:${width}px" data-index="${i}"></div>`;
const safe = (title) => html`<h1>${title}</h1>`;
const message = (name) => `Hello ${name}, welcome back`;
