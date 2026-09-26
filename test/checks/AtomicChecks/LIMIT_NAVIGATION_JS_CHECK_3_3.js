function onWindowOrNavigate(ev, target) {
  if (!target.startsWith('https://')) ev.preventDefault();
}
webContents.on('will-navigate', (ev, target) => onWindowOrNavigate(ev, target));
webContents.on('will-navigate', (ev, target) => externalHelper(ev, target));
webContents.on('will-navigate', (ev, target) => console.log(target));
