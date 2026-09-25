// Minimal console logger. Debug output is enabled with DEBUG=electronegativity (or DEBUG=*).
const debugEnabled = /(^|,)\s*(\*|electronegativity)\s*(,|$)/.test(process.env.DEBUG || '');

const logger = {
  debug: (...args) => { if (debugEnabled) console.debug(...args); },
  info: (...args) => console.info(...args),
  warn: (...args) => console.warn(...args),
  error: (...args) => console.error(...args),
};

export default logger;
