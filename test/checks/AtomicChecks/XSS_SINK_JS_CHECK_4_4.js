// compiled React/Preact and Vue HTML props, as bundles ship them
function getHtml(html) { return { __html: html }; }
const Toast = ({ message }) => jsx("div", { className: "toast-body", dangerouslySetInnerHTML: getHtml(message) });
const Item = (r) => h("li", { dangerouslySetInnerHTML: { __html: r } });
function apply(o, d) { o.dangerouslySetInnerHTML = { __html: d.html }; }
const render = (ctx) => createElementVNode("div", { innerHTML: ctx.note.content }, null, 8);
// not reported: constant markup, and an object that is not element props
const Logo = () => jsx("span", { dangerouslySetInnerHTML: { __html: "<b>Logo</b>" } });
const options = { innerHTML: userValue };
