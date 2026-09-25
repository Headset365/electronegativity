document.addEventListener('drop', (e) => {
  const first = e.dataTransfer.files[0].path;
  for (const droppedFile of e.dataTransfer.files) console.log(droppedFile.path);
  const p = path.join(dir, 'x');
});
