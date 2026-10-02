// an allowlist that compares host names only: http:// on the allowed host passes
const { app } = require("electron");
app.on("web-contents-created", (_, contents) => {
  contents.on("will-navigate", (event, url) => {
    const { hostname } = new URL(url);
    if (hostname !== "app.example.com") event.preventDefault();
  });
});
