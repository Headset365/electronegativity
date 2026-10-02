const { session } = require("electron");

session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  if (details.url.startsWith("https://app.test/app")) details.responseHeaders["content-security-policy"] = "*";
  callback(details);
});