element.innerHTML = message.body;
container.insertAdjacentHTML('beforeend', `<li>${item.name}</li>`);
document.write(location.hash);
const View = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />;
element.innerHTML = '<b>static</b>';
element.innerHTML = DOMPurify.sanitize(message.body);
const Safe = ({ html }) => <div dangerouslySetInnerHTML={{ __html: sanitize(html) }} />;
element.textContent = message.body;
