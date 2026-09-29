// How much an installer or package may unpack to. A crafted archive can declare, or inflate to, any size: without a cap
// one small file exhausts the scanning machine's memory or disk. ELECTRONEGATIVITY_MAX_UNPACK_MB raises it for very
// large apps.
const configured = Number(process.env.ELECTRONEGATIVITY_MAX_UNPACK_MB);

/** The largest single decoded stream (a 7z folder, a zip entry, an NSIS block), in bytes. */
export const MAX_STREAM = (Number.isFinite(configured) && configured > 0 ? configured : 2048) * 1024 * 1024;
/** The most one extraction writes to disk, in bytes. */
export const MAX_TOTAL = 4 * MAX_STREAM;

export const limitMessage = (what, size, limit = MAX_STREAM) =>
  `${what}: ${size} bytes unpacked is more than the ${Math.round(limit / 1048576)} MB limit (raise it with ELECTRONEGATIVITY_MAX_UNPACK_MB)`;
