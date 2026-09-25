const version = await window.app.getVersion();
document.getElementById('title').textContent = `Version ${version}`;
window.app.onUpdateAvailable((next) => {
  document.getElementById('title').textContent = `Update available: ${next}`;
});
